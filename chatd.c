#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>

#include <glib.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>

/* Definitions */
/* Files */
const char LOG_FILE[] = "chatd.log";
const char PRIVATE_KEY[] = "../ser_key.pem";
const char SERVER_CERTIFICATE[] = "../ser_crt.pem";
const char PASSWORD_KEYFILE[] = "passwords.ini";
/* Constants */
const int MAX_CLIENTS = 256;
const int MAX_MESSAGE_SIZE = 1 << 15;
const int MAX_NAME_LENGTH = 1 << 6;
const time_t TIMEOUT = 60 * 5; /* Timeout in seconds */
const time_t PASSWORD_ATTEMPT_TIMEOUT = 30;
const int EMPTY_CONNECTION = 0;
/* Strings */
const char CONNECTED_STR[] = "connected";
const char DISCONNECTED_STR[] = "disconnected";
const char PASSWORD_GROUP[] = "passwords";
/* Hash settings */
const unsigned char SALTY[] = {'A', 'r', 'n', 'a', 'R'};
/* We had the hash iterations higher but then it was too slow on skel. Tt needs to be higher to prevent brute force attacks */
const int HASH_ITERATIONS = 13371;
const int HASH_SIZE = 1 << 6;

/* Structs */
struct client {
    time_t timestamp;
    SSL* ssl_conn;
    gchar* ip_port_str;
    gchar* username;
    int fd;
    int authenticated;
    int failed_tries;
};

struct chatroom {
    gchar* name;
    gchar* description;
    GHashTable* users_set;
};

enum AuthResult { DENIED, FAILED, REGISTERED, SUCCESS };

static int keep_running = 1;

void sig_handler() {
    keep_running = 0;
}

/* This can be used to build instances of GTree that index on
the address of a connection. */
int sockaddr_in_cmp(const void *addr1, const void *addr2)
{
    const struct sockaddr_in *_addr1 = addr1;
    const struct sockaddr_in *_addr2 = addr2;

    /* If either of the pointers is NULL or the addresses
    belong to different families, we abort. */
    g_assert((_addr1 == NULL) || (_addr2 == NULL) ||
    (_addr1->sin_family != _addr2->sin_family));

    if (_addr1->sin_addr.s_addr < _addr2->sin_addr.s_addr) {
        return -1;
    } else if (_addr1->sin_addr.s_addr > _addr2->sin_addr.s_addr) {
        return 1;
    } else if (_addr1->sin_port < _addr2->sin_port) {
        return -1;
    } else if (_addr1->sin_port > _addr2->sin_port) {
        return 1;
    }
    return 0;
}


/* This can be used to build instances of GTree that index on
the file descriptor of a connection. */
gint fd_cmp(gconstpointer fd1,  gconstpointer fd2, gpointer G_GNUC_UNUSED data)
{
    return GPOINTER_TO_INT(fd1) - GPOINTER_TO_INT(fd2);
}

/* Used in hash tables to delete entries */
void destroy_ptr(gpointer p) {
    g_free(p);
}

void destroy_chatroom(gpointer p) {
    struct chatroom* room = (struct chatroom*) p;
    g_free(room->name);
    g_free(room->description);
    g_hash_table_destroy(room->users_set);
}

/* Set up the OpenSSL library */
SSL_CTX* init_ssl_ctx() {
    SSL_library_init();
    SSL_load_error_strings();
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLSv1_server_method());

    if (SSL_CTX_use_certificate_file(ssl_ctx, SERVER_CERTIFICATE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, PRIVATE_KEY, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_check_private_key(ssl_ctx) == 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (ssl_ctx == NULL) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ssl_ctx;
}

/* Log the response to the file specified by log_file in append mode so we don't lose past information */
void log_request(struct sockaddr_in* client, const gchar* message) {
    FILE* file = fopen(LOG_FILE, "a");

    GTimeVal current_time;
    g_get_current_time(&current_time);
    gchar * datestring = g_time_val_to_iso8601(&current_time);
    fprintf(file, "%s : %s:%hu %s\n",
            datestring,
            inet_ntoa(client->sin_addr),
            client->sin_port,
            message);
    g_free(datestring);
    fclose(file);
}

/* Checks for timeout */
int timed_out(time_t connection_time, time_t timeout) {
    time_t now = time(NULL);
    if (now - connection_time >= timeout) {
        return 1;
    }
    return 0;
}

void clear_client(struct client* user) {
    user->fd = 0;
    user->ssl_conn = NULL;
    user->ip_port_str = NULL;
    user->timestamp = 0;
    user->authenticated = 0;
    user->timestamp = 0;
    user->failed_tries = 0;
}

int write_user_list(GHashTable* user_to_chatroom, struct client clients[MAX_CLIENTS], gchar* buffer) {
    memset(buffer, 0, MAX_MESSAGE_SIZE);
    int used = 0;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].ssl_conn != NULL) {
            struct client* user = &clients[i];
            struct chatroom* current_chatroom = g_hash_table_lookup(user_to_chatroom, user);
            gchar* user_entry = g_strdup_printf("%s - %s - %s",
                user->username == NULL ? "Not logged in" : user->username,
                user->ip_port_str,
                current_chatroom == NULL ? "Not in a chatroom" : current_chatroom->name);
            int len = strlen(user_entry);
            if (len + used > MAX_MESSAGE_SIZE) break;
            for (int j = 0; j < len; j++) {
                if (user_entry[j] == '\0') break;
                buffer[used++] = user_entry[j];
            }
            buffer[used++] = '\n';
            g_free(user_entry);
        }
    }
    /* Replace the last newline with a null terminator */
    buffer[used - 1] = '\0';
    return used;
}

int write_chatroom_list(GHashTable* chatroom_to_info, gchar* buffer) {
    memset(buffer, 0, MAX_MESSAGE_SIZE);
    int used = 0;
    /* Iterate over all the chatrooms in our hash table */
    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, chatroom_to_info);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        gchar* chatroom_name = (gchar*) key;
        struct chatroom* chatroom = (struct chatroom*) value;
        gchar* user_count_str = g_strdup_printf(" - %s - %d users\n",
            chatroom->description,
            g_hash_table_size(chatroom->users_set));
        /* Check if there is enough space for the chatroom name and the number of users */
        int len = strlen(chatroom_name) + strlen(user_count_str);
        if (len + used > MAX_MESSAGE_SIZE) {
            int pos = MIN(used, MAX_MESSAGE_SIZE - 5);
            strcpy(buffer + pos - 1, "\n...");
            used += 4;
            break;
        } else {
            for (int j = 0; j < len; j++) {
                if (chatroom_name[j] == '\0') break;
                buffer[used++] = chatroom_name[j];
            }
            for (int j = 0; j < len; j++) {
                if (user_count_str[j] == '\0') break;
                buffer[used++] = user_count_str[j];
            }
        }
        g_free(user_count_str);
    }
    /* Replace the last newline with a null terminator */
    buffer[used - 1] = '\0';
    return used;
}

void create_chatroom(GHashTable* chatroom_to_info, gchar* name, gchar* description) {
    gchar* key = g_strdup(name);
    gchar* _name = g_strdup(name);
    gchar* _description = g_strdup(description);
    struct chatroom* new_room = malloc(sizeof(struct chatroom));
    new_room->name = _name;
    new_room->description = _description;
    new_room->users_set = g_hash_table_new(g_direct_hash, g_direct_equal);
    g_hash_table_insert(chatroom_to_info, key, new_room);
}

void broadcast_message(struct chatroom* chatroom, gchar* message) {
    int len = strlen(message);
    GHashTableIter iter;
    gpointer key, value;
    /* For every user in the chatroom we send the message to their connection */
    g_hash_table_iter_init(&iter, chatroom->users_set);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        struct client* other_user = (struct client*) key;
        SSL_write(other_user->ssl_conn, message, len);
    }
}

void remove_from_chatroom(GHashTable* user_to_chatroom, struct client* client) {
    struct chatroom* current_chatroom = g_hash_table_lookup(user_to_chatroom, client);
    if (current_chatroom != NULL) {
        g_hash_table_remove(current_chatroom->users_set, client);
        g_hash_table_remove(user_to_chatroom, client);
        gchar* leave_message = g_strdup_printf("%s just left the chatroom!", client->username);
        broadcast_message(current_chatroom, leave_message);
        g_free(leave_message);
    }
}

int add_to_chatroom(GHashTable* chatroom_to_info, GHashTable* user_to_chatroom, struct client* client, gchar* chatroom_to_join) {
    struct chatroom* chatroom = g_hash_table_lookup(chatroom_to_info, chatroom_to_join);
    if (chatroom != NULL) {
        gchar* join_message = g_strdup_printf("%s just joined the chatroom!", client->username);
        broadcast_message(chatroom, join_message);
        g_free(join_message);
        g_hash_table_add(chatroom->users_set, client);
        g_hash_table_insert(user_to_chatroom, client, chatroom);
        return 1;
    }
    return 0;
}

void remove_clear_client(GHashTable* user_to_chatroom, GHashTable* username_to_user, struct client* user, const gchar* reason) {
    struct sockaddr_in client;
    socklen_t client_len = sizeof(client);
    getpeername(user->fd, (struct sockaddr*) &client, &client_len);

    /* Log the disconnect */
    log_request(&client, reason);
    /* Remove user from all relevant hash tables */
    if (user->username != NULL) {
        g_hash_table_remove(username_to_user, user->username);
    }
    remove_from_chatroom(user_to_chatroom, user);
    /* Close the OpenSSL connection */
    SSL_shutdown(user->ssl_conn);
    SSL_free(user->ssl_conn);
    close(user->fd);
    fprintf(stdout, "Closed connection from %s:%hu\n", inet_ntoa(client.sin_addr), client.sin_port);
    /* Clear the struct so another client may connect and use it */
    g_free(user->ip_port_str);
    if (user->username != NULL) {
        g_free(user->username);
    }
    clear_client(user);
}

/* Returns enum SUCCESS, REGISTERED, FAILED */
enum AuthResult check_authentication(GKeyFile* usr_pw_keyfile, struct client* user, gchar* username, gchar* password) {
    /* Get this connections info since we might need it */
    struct sockaddr_in client;
    socklen_t client_len = sizeof(client);
    int ret;
    getpeername(user->fd, (struct sockaddr*) &client, &client_len);
    /* Hash the password */
    guchar pw_hash[HASH_SIZE];
    PKCS5_PBKDF2_HMAC(password, strlen(password), SALTY, sizeof(SALTY),
        HASH_ITERATIONS, EVP_sha256(), HASH_SIZE, (guchar*) &pw_hash);
    gchar *pw_64 = g_base64_encode(pw_hash, HASH_SIZE);
    /* Get the saved password */
    gchar* saved_pw_64 = g_key_file_get_string(usr_pw_keyfile, PASSWORD_GROUP, username, NULL);
    if (saved_pw_64 == NULL) {
        /* Register the user */
        g_key_file_set_string(usr_pw_keyfile, PASSWORD_GROUP, username, pw_64);
        g_key_file_save_to_file(usr_pw_keyfile, PASSWORD_KEYFILE, NULL);
        ret = REGISTERED;
    } else if (strncmp(saved_pw_64, pw_64, strlen(saved_pw_64)) == 0) {
        /* User is authenticated */
        gchar* success = g_strdup_printf("%s authenticated", username);
        log_request(&client, success);
        g_free(success);
        ret = SUCCESS;
    } else {
        /* A failed authentication attempt */
        ret = FAILED;
        gchar* error = g_strdup_printf("%s authentication error", username);
        log_request(&client, error);
        g_free(error);
        if (++(user->failed_tries) > 2) {
            ret = DENIED;
        }
    }
    g_free(saved_pw_64);
    g_free(pw_64);
    return ret;
}

/* Returns enum SUCCESS, REGISTERED, DENIED or FAILED */
enum AuthResult update_authentication_password(GKeyFile* usr_pw_keyfile, struct client* user, gchar* username, gchar* old_password, gchar* new_password) {
    /* Get this connections info since we might need it */
    struct sockaddr_in client;
    socklen_t client_len = sizeof(client);
    getpeername(user->fd, (struct sockaddr*) &client, &client_len);
    /* Hash the old password */
    guchar old_pw_hash[HASH_SIZE];
    PKCS5_PBKDF2_HMAC(old_password, strlen(old_password), SALTY, sizeof(SALTY),
                      HASH_ITERATIONS, EVP_sha256(), HASH_SIZE, (guchar*) &old_pw_hash);
    gchar *old_pw_64 = g_base64_encode(old_pw_hash, HASH_SIZE);
    /* Get the saved password */
    gchar* saved_pw_64 = g_key_file_get_string(usr_pw_keyfile, PASSWORD_GROUP, username, NULL);
    if (strncmp(saved_pw_64, old_pw_64, strlen(saved_pw_64)) == 0) {
        /* User is authenticated */
        gchar* success = g_strdup_printf("%s authenticated for pasword change", user->username);
        log_request(&client, success);
        g_free(success);

        /* Hash the new password */
        guchar new_pw_hash[HASH_SIZE];
        PKCS5_PBKDF2_HMAC(new_password, strlen(new_password), SALTY, sizeof(SALTY),
                          HASH_ITERATIONS, EVP_sha256(), HASH_SIZE, (guchar*) &new_pw_hash);
        gchar *new_pw_64 = g_base64_encode(new_pw_hash, HASH_SIZE);

        /* Update the user */
        g_key_file_set_string(usr_pw_keyfile, PASSWORD_GROUP, username, new_pw_64);
        g_key_file_save_to_file(usr_pw_keyfile, PASSWORD_KEYFILE, NULL);
        return SUCCESS;
    } else {
        /* A failed authentication attempt */
        gchar* error = g_strdup_printf("%s authentication error for password change", user->username);
        log_request(&client, error);
        g_free(error);
        if (++(user->failed_tries) > 2) {
            return DENIED;
        }
    }
    g_free(saved_pw_64);
    g_free(old_pw_64);
    return FAILED;
}

void send_error(struct client* user, gchar* error_msg) {
    gchar* error = g_strdup_printf("ERROR: %s", error_msg);
    SSL_write(user->ssl_conn, error, strlen(error));
    g_free(error);
}

void send_notification(struct client* user, gchar* notification) {
    gchar* error = g_strdup_printf("NOTIFY: %s", notification);
    SSL_write(user->ssl_conn, error, strlen(error));
    g_free(error);
}

int dice_roll() {
    return (int) floor(drand48() * 6.0) + 1;
}

int main(int argc, char **argv)
{
    /* To shut down the server send a SIGINT */
    if (signal(SIGINT, sig_handler) == SIG_ERR)
        printf("\ncan't catch SIGINT\n");

    struct sockaddr_in server, client;
    socklen_t client_len = sizeof(client);

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const int requested_port = strtol(argv[1], NULL, 10);

    SSL_CTX *ssl_ctx = init_ssl_ctx();

    /* Create and bind a TCP socket */
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket returned an error, terminating");
        exit(errno);
    }

    /* Network functions need arguments in network byte order instead of
    host byte order. The macros htonl, htons convert the values. */
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(requested_port);

    ssize_t ret = bind(server_fd, (struct sockaddr *) &server, (socklen_t) sizeof(server));
    if (ret < 0) {
        perror("bind returned an error, terminating");
        exit(errno);
    }

    /* Before the server can accept messages, it has to listen to the
    welcome port. A backlog of MAX_CLIENTS connections is allowed. */
    if (listen(server_fd, MAX_CLIENTS) < 0) {
        perror("listen returned an error, terminating");
        exit(errno);
    }

    /* Create the clients array which will hold all of our connections */
    struct client clients_array[MAX_CLIENTS];
    memset(&clients_array, 0, sizeof(clients_array));

    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients_array[i].ssl_conn = NULL;
        clients_array[i].timestamp = 0;
    }

    /* Create username->last login timestamp, username->user, chatroom->users and user->chatroom hash tables  */
    GHashTable* last_login_attempt = g_hash_table_new_full(g_str_hash, g_str_equal, destroy_ptr, destroy_ptr);
    GHashTable* roll_challenges = g_hash_table_new(g_direct_hash, g_direct_equal);
    GHashTable* username_to_user = g_hash_table_new_full(g_str_hash, g_str_equal, destroy_ptr, NULL);
    GHashTable* chatroom_to_info = g_hash_table_new_full(g_str_hash, g_str_equal, destroy_ptr, destroy_chatroom);
    GHashTable* user_to_chatroom = g_hash_table_new(g_direct_hash, g_direct_equal);
    /* Add some chatroom entries */
    create_chatroom(chatroom_to_info, "TSAM", "problem discussion");
    create_chatroom(chatroom_to_info, "TVIUND", "social discussion");
    create_chatroom(chatroom_to_info, "ILLEGAL", "ask about something illegal");

    /* Load the keyfile to hold username->password entries */
    GKeyFile* usr_pw_keyfile = g_key_file_new();
    g_key_file_load_from_file(usr_pw_keyfile, PASSWORD_KEYFILE,
        G_KEY_FILE_NONE, NULL);

    fd_set readfds;
    while (keep_running) {
        int client_fd;
        /* Zero out every entry in readfds */
        FD_ZERO(&readfds);
        /* Set the first socket which will accept connections for us */
        FD_SET(server_fd, &readfds);
        int max_fd = server_fd;
        /* Specify maximum select time */
        struct timeval tv;
        tv.tv_sec = 30;
        tv.tv_usec = 0;
        for (int i = 0; i < MAX_CLIENTS; i++)
        {
            struct client curr = clients_array[i];
            if(curr.ssl_conn != NULL) {
                FD_SET(curr.fd, &readfds);
            }
            if(curr.fd > max_fd) {
                max_fd = curr.fd;
            }
        }
        int ret = select(max_fd + 1, &readfds, NULL, NULL, &tv);
        if (ret < 0) {
            /* Select returns an error if we catch a signal so we use it to quit gracefully on Ctrl-C */
            perror("select");
            if (keep_running == 0)
                break;
            else
                exit(EXIT_FAILURE);
        } else if (ret == 0) {
            fprintf(stdout, "No messages received for 30 seconds, still listening on port %d...\n", requested_port);
            /* We don't do anything here so that connections are still checked for timeouts */
        }
        /* Accept new connections */
        if (FD_ISSET(server_fd, &readfds))
        {
            if ((client_fd = accept(server_fd, (struct sockaddr *) &client, &client_len)) < 0) {
                perror("accept");
                exit(errno);
            }
            fprintf(stdout, "New connection from %s:%hu\n", inet_ntoa(client.sin_addr), client.sin_port);
            log_request(&client, CONNECTED_STR);

            /* Set up all the OpenSSL requirements */
            SSL* ssl = SSL_new(ssl_ctx);
            SSL_set_fd(ssl, client_fd);
            if (SSL_accept(ssl) <= 0) {
                ERR_print_errors_fp(stderr);
                printf("SSL_accept on new client");
                SSL_shutdown(ssl);
                SSL_free(ssl);
                close(client_fd);
                log_request(&client, "ssl_accept failed");
            } else {
                /* Search for an empty client slot */
                for (int i = 0; i < MAX_CLIENTS; i++) {
                    if (clients_array[i].ssl_conn == NULL) {
                        /* Initalize the new client */
                        clients_array[i].ssl_conn = ssl;
                        clients_array[i].fd = client_fd;
                        clients_array[i].timestamp = time(NULL);
                        clients_array[i].ip_port_str = g_strdup_printf("%s:%hu", inet_ntoa(client.sin_addr), client.sin_port);
                        SSL_write(ssl, "WELCOME: Hello from the other side!", sizeof("WELCOME: Hello from the other side!"));
                        break;
                    } else if (i == MAX_CLIENTS - 1) {
                        /* The last spot is full */
                        SSL_write(ssl, "ERROR: Unfortunately the server is full at the moment!", sizeof("ERROR: Unfortunately the server is full at the moment!"));
                        SSL_shutdown(ssl);
                        SSL_free(ssl);
                        close(client_fd);
                        log_request(&client, DISCONNECTED_STR);
                    }
                }
            }
        }
        /* For each client connected, check for new messages and handle them in order */
        for (int i = 0; i < MAX_CLIENTS; i++) {
            struct client* user = &clients_array[i];
            if (user->fd == EMPTY_CONNECTION) {
                continue;
            }
            if (FD_ISSET(user->fd, &readfds)) {
                gchar buf[MAX_MESSAGE_SIZE];
                memset(&buf, 0, sizeof(buf));
                int sz = SSL_read(user->ssl_conn, &buf, sizeof(buf));
                if (sz == 0) {
                    /* Shut down the connection */
                    remove_clear_client(user_to_chatroom, username_to_user, user, DISCONNECTED_STR);
                } else {
                    user->timestamp = time(NULL);
                    /* User is not authenticated and is trying to join a lobby or send messages */
                    if ((strncmp("USER", buf, 4) != 0) && !user->authenticated) {
                        send_error(user, "Please login with /user [username]");
                        continue;
                    }
                    if (strncmp("WHO", buf, 3) == 0) {
                        gchar user_list[MAX_MESSAGE_SIZE];
                        int sz = write_user_list(user_to_chatroom, (struct client *) &clients_array, user_list);
                        SSL_write(user->ssl_conn, user_list, sz);
                    } else if (strncmp("LIST", buf, 4) == 0) {
                        gchar chatroom_list[MAX_MESSAGE_SIZE];
                        int sz = write_chatroom_list(chatroom_to_info, chatroom_list);
                        SSL_write(user->ssl_conn, chatroom_list, sz);
                    } else if (strncmp("JOIN", buf, 4) == 0) {
                        int i = 5;
                        while (buf[i] != '\0' && isspace(buf[i])) { i++; }
                        if (buf[i] != '\0') {
                            gchar* chatroom_to_join = g_strdup(&(buf[i]));
                            remove_from_chatroom(user_to_chatroom, user);
                            if (add_to_chatroom(chatroom_to_info, user_to_chatroom, user, chatroom_to_join)) {
                                gchar* join_notify = g_strdup_printf("JOIN: %s joined successfully", chatroom_to_join);
                                SSL_write(user->ssl_conn, join_notify, strlen(join_notify));
                                g_free(join_notify);
                            } else {
                                send_error(user, "Chatroom could not be found/joined");
                            }
                            g_free(chatroom_to_join);
                        }
                    } else if (strncmp("MSG", buf, 3) == 0) {
                        int i = 4;
                        while (buf[i] != '\0' && isspace(buf[i])) { i++; }
                        if (buf[i] != '\0') {
                            gchar* message = g_strdup_printf("%s: %s", user->username, &(buf[i]));
                            /* Find the users current chatroom */
                            struct chatroom* current_chatroom = g_hash_table_lookup(user_to_chatroom, user);
                            if (current_chatroom != NULL) {
                                broadcast_message(current_chatroom, message);
                            } else {
                                send_error(user, "You are currently not a member of any chatroom");
                            }
                            g_free(message);
                        }
                    } else if (strncmp("ROLL", buf, 4) == 0) {
                        int i = 5;
                        while (buf[i] != '\0' && isspace(buf[i])) { i++; }
                        gchar* challenged = strdup(&buf[i]);
                        struct client* other_user = g_hash_table_lookup(username_to_user, challenged);
                        if (other_user == NULL) {
                            gchar* error = g_strdup_printf("Could not find user %s", challenged);
                            send_error(user, error);
                            g_free(error);
                        } else {
                            /* Check if this user has been challenged by the other user */
                            struct client* other_challenged = g_hash_table_lookup(roll_challenges, other_user);
                            if (other_challenged == user) {
                                /* Do the roll */
                                int user_score = dice_roll() + dice_roll();
                                int other_user_score = dice_roll() + dice_roll();
                                gchar* score = g_strdup_printf("%s rolled: %d, %s rolled: %d",
                                    other_user->username,
                                    other_user_score,
                                    user->username,
                                    user_score);
                                gchar* winner = g_strdup_printf("%s, you win!", score);
                                gchar* loser = g_strdup_printf("%s, you lose!", score);
                                gchar* tie = g_strdup_printf("%s, it's a tie!", score);
                                if (user_score > other_user_score) {
                                    send_notification(user, winner);
                                    send_notification(other_user, loser);
                                } else if (user_score < other_user_score) {
                                    send_notification(user, loser);
                                    send_notification(other_user, winner);
                                } else {
                                    send_notification(user, tie);
                                    send_notification(other_user, tie);
                                }
                                g_free(winner);
                                g_free(loser);
                                g_free(tie);
                                g_free(score);
                                g_hash_table_remove(roll_challenges, other_user);
                            } else {
                                /* Save the roll request and notify the other user */
                                g_hash_table_insert(roll_challenges, user, other_user);
                                gchar* notification = g_strdup_printf("User %s has challenged you to a roll! Type /roll %s to accept",
                                    user->username,
                                    user->username);
                                send_notification(other_user, notification);
                                g_free(notification);
                                notification = g_strdup_printf("User %s has been challenged to a roll!",
                                    other_user->username);
                                send_notification(user, notification);
                                g_free(notification);
                            }
                        }
                    } else if (strncmp("SAY", buf, 3) == 0) {
                        int i = 4;
                        while (buf[i] != '\0' && isspace(buf[i])) { i++; }
                        gchar* received = g_strdup(&(buf[i]));
                        gchar** receiver_message = g_strsplit(received, "\r\n", -1);
                        /* No message was received */
                        if (receiver_message[1] == NULL) continue;
                        gchar* receiver = receiver_message[0];
                        gchar* message = receiver_message[1];

                        struct client* target = g_hash_table_lookup(username_to_user, receiver);
                        if (target != NULL) {
                            gchar* transmit = g_strdup_printf("Private message from %s: %s", user->username, message);
                            SSL_write(target->ssl_conn, transmit, strlen(transmit));
                            g_free(transmit);
                        } else {
                            gchar* error = g_strdup_printf("Could not find user %s", receiver);
                            send_error(user, error);
                            g_free(error);
                        }
                        g_free(received);
                        g_strfreev(receiver_message);
                    } else if (strncmp("USER", buf, 4) == 0) {
                        if (user->authenticated) {
                            send_error(user, "Already logged in");
                            continue;
                        }
                        int i = 5;
                        while (buf[i] != '\0' && isspace(buf[i])) { i++; }

                        gchar* received = g_strdup(&(buf[i]));
                        gchar** username_pass = g_strsplit(received, "\r\n", -1);
                        gchar* username = username_pass[0];
                        gchar* password = username_pass[1];
                        /* Check the last login attempt time of this username */
                        time_t* last_login = g_hash_table_lookup(last_login_attempt, username);
                        if (last_login == NULL) {
                            time_t* time_now = malloc(sizeof(time_t));
                            *time_now = time(NULL);
                            g_hash_table_insert(last_login_attempt, g_strdup(username), time_now);
                        } else if (!timed_out(*last_login, PASSWORD_ATTEMPT_TIMEOUT)) {
                            /* If the last login attempt was less than PASSWORD_ATTEMPT_TIMEOUT seconds ago */
                            send_error(user, "Too frequent login attempts, please wait before trying again");
                            continue;
                        } else {
                            *last_login = time(NULL);
                        }
                        /* No password was received */
                        if (username_pass[1] == NULL) continue;
                        /* Set the username and save to a reference table */

                        enum AuthResult authed = check_authentication(usr_pw_keyfile, user, username, password);
                        if (authed == SUCCESS || authed == REGISTERED) {
                            user->authenticated = 1;
                            user->failed_tries = 0;
                            user->username = g_strdup(username);
                            g_hash_table_insert(username_to_user, g_strdup(username), user);
                            gchar* error = g_strdup_printf("LOGIN: %s %s", username,
                                authed == REGISTERED ? "registered" : "authenticated");
                            SSL_write(user->ssl_conn, error, strlen(error));
                            g_free(error);
                        } else if (authed == DENIED) {
                            send_error(user, "Too many failed login attempts");
                            remove_clear_client(user_to_chatroom, username_to_user, user, DISCONNECTED_STR);
                        } else {
                            gchar* error = g_strdup_printf("Invalid credentials for user %s", username);
                            send_error(user, error);
                            g_free(error);
                        }
                        g_free(received);
                        g_strfreev(username_pass);
                    } else if (strncmp("NEWPASS", buf, 7) == 0) {
                        int i = 7;
                        while (buf[i] != '\0' && isspace(buf[i])) { i++; }

                        gchar* received = g_strdup(&(buf[i]));
                        gchar** username_pass = g_strsplit(received, "\r\n", -1);

                        gchar* username = username_pass[0];
                        gchar* old_password = username_pass[1];
                        gchar* new_password = username_pass[2];

                        /* Check the last login attempt time of this username */
                        unsigned long* last_login = g_hash_table_lookup(last_login_attempt, username);
                        if (last_login == NULL) {
                            int* time_now = malloc(sizeof(last_login));
                            *time_now = time(NULL);
                            g_hash_table_insert(last_login_attempt, g_strdup(username), time_now);
                        } else if (!timed_out(*last_login, PASSWORD_ATTEMPT_TIMEOUT)) {
                            /* If the last login attempt was less than PASSWORD_ATTEMPT_TIMEOUT seconds ago */
                            send_error(user, "Too frequent login attempts, please wait before trying again");
                            continue;
                        } else {
                            *last_login = time(NULL);
                        }
                        /* No password was received */
                        if (username_pass[1] == NULL) continue;
                        /* Set the username and save to a reference table */

                        enum AuthResult authed = update_authentication_password(usr_pw_keyfile, user, username, old_password, new_password);
                        if (authed == SUCCESS) {
                            gchar* error = g_strdup_printf("LOGIN: %s updated", username);
                            SSL_write(user->ssl_conn, error, strlen(error));
                            g_free(error);
                        } else if (authed == DENIED) {
                            send_error(user, "Update failed");
                        } else {
                            gchar* error = g_strdup_printf("Invalid credentials for user %s", username);
                            send_error(user, error);
                            g_free(error);
                        }
                        g_free(received);
                        g_strfreev(username_pass);
                    }
                }
            } else if (timed_out(user->timestamp, TIMEOUT)) {
                send_error(user, "You have been inactive for too long and will be disconnected");
                remove_clear_client(user_to_chatroom, username_to_user, user, "timed out");
            }
        }
    }
    printf("Server has quit gracefully\n");
    /* Free allocated memory */
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients_array[i].ip_port_str != NULL) {
            remove_clear_client(user_to_chatroom, username_to_user, &clients_array[i], DISCONNECTED_STR);
        }
    }
    g_hash_table_destroy(roll_challenges);
    g_hash_table_destroy(last_login_attempt);
    g_hash_table_destroy(username_to_user);
    g_hash_table_destroy(user_to_chatroom);
    g_hash_table_destroy(chatroom_to_info);
    g_key_file_save_to_file(usr_pw_keyfile, PASSWORD_KEYFILE, NULL);
    g_key_file_free(usr_pw_keyfile);
    /* Shut down OpenSSL and the socket */
    close(server_fd);
    SSL_CTX_free(ssl_ctx);
    /* Copy pasted OpenSSL shutdown functions */
    ERR_free_strings();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();

    exit(EXIT_SUCCESS);
}
