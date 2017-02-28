#include <assert.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <signal.h>
#include <arpa/inet.h>
#include <glib.h>

/* Secure socket layer headers */
#include <openssl/ssl.h>
#include <openssl/err.h>

/* For nicer interaction, we use the GNU readline library. */
#include <readline/readline.h>
#include <readline/history.h>

/* Constants */
const int MAX_MESSAGE_SIZE = 1 << 15;
const char CLIENT_CERTIFICATE[] = "../cli_cert.pem";
const char CLIENT_KEY[] = "../cli_key.pem";

/* This variable holds a file descriptor of a pipe on which we send a
* number if a signal is received. */
static int exitfd[2];

/* If someone kills the client, it should still clean up the readline
library, otherwise the terminal is in a inconsistent state. The
signal number is sent through a self pipe to notify the main loop
of the received signal. This avoids a race condition in select. */
void
signal_handler(int signum)
{
    int _errno = errno;
    if (write(exitfd[1], &signum, sizeof(signum)) == -1 && errno != EAGAIN) {
        abort();
    }
    fsync(exitfd[1]);
    errno = _errno;
}


static void initialize_exitfd(void)
{
    /* Establish the self pipe for signal handling. */
    if (pipe(exitfd) == -1) {
        perror("pipe()");
        exit(EXIT_FAILURE);
    }

    /* Make read and write ends of pipe nonblocking */
    int flags;
    flags = fcntl(exitfd[0], F_GETFL);
    if (flags == -1) {
        perror("fcntl-F_GETFL");
        exit(EXIT_FAILURE);
    }
    flags |= O_NONBLOCK;                /* Make read end nonblocking */
    if (fcntl(exitfd[0], F_SETFL, flags) == -1) {
        perror("fcntl-F_SETFL");
        exit(EXIT_FAILURE);
    }

    flags = fcntl(exitfd[1], F_GETFL);
    if (flags == -1) {
        perror("fcntl-F_SETFL");
        exit(EXIT_FAILURE);
    }
    flags |= O_NONBLOCK;                /* Make write end nonblocking */
    if (fcntl(exitfd[1], F_SETFL, flags) == -1) {
        perror("fcntl-F_SETFL");
        exit(EXIT_FAILURE);
    }

    /* Set the signal handler. */
    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;           /* Restart interrupted reads()s */
    sa.sa_handler = signal_handler;

    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
}


/* The next two variables are used to access the encrypted stream to
* the server. The socket file descriptor server_fd is provided for
* select (if needed), while the encrypted communication should use
* server_ssl and the SSL API of OpenSSL.
*/
static int server_fd;
static SSL *server_ssl;

/* This variable shall point to the name of the user. The initial value
is NULL. Set this variable to the username once the user managed to be
authenticated. */
static char *user;

/* This variable shall point to the name of the chatroom. The initial
value is NULL (not member of a chat room). Set this variable whenever
the user changed the chat room successfully. */
static char *chatroom;

/* This prompt is used by the readline library to ask the user for
* input. It is good style to indicate the name of the user and the
* chat room he is in as part of the prompt. */
static char *prompt;



/* When a line is entered using the readline library, this function
gets called to handle the entered line. Implement the code to
handle the user requests in this function. The client handles the
server messages in the loop in main(). */
void readline_callback(char *line)
{
    char buffer[MAX_MESSAGE_SIZE];
    if (NULL == line) {
        rl_callback_handler_remove();
        signal_handler(SIGTERM);
        return;
    }
    if (strlen(line) > 0) {
        add_history(line);
    }
    if ((strncmp("/bye", line, 4) == 0) ||
    (strncmp("/quit", line, 5) == 0)) {
        rl_callback_handler_remove();
        signal_handler(SIGTERM);
        return;
    } else if (strncmp("/join", line, 5) == 0) {
        int i = 5;
        /* Skip whitespace */
        while (line[i] != '\0' && isspace(line[i])) { i++; }
        if (line[i] == '\0') {
            write(STDOUT_FILENO, "Usage: /join chatroom\n", 22);
            fsync(STDOUT_FILENO);
            return;
        }
        snprintf(buffer, MAX_MESSAGE_SIZE, "JOIN %s", &(line[i]));
        /* Process and send this information to the server. */
        SSL_write(server_ssl, buffer, strlen(buffer) + 1);
		return;
    } else if (strncmp("/list", line, 5) == 0) {
        /* Query all available chat rooms */
        SSL_write(server_ssl, "LIST", 5);
    } else if (strncmp("/roll", line, 5) == 0) {
        /* roll dice */
        int i = 5;
        while (line[i] != '\0' && isspace(line[i])) { i++; }
        if (line[i] == '\0') {
            write(STDOUT_FILENO, "Usage: /roll username\n", 21);
            fsync(STDOUT_FILENO);
            return;
        }
        gchar* username = strdup(&line[i]);
        snprintf(buffer, MAX_MESSAGE_SIZE, "ROLL %s", username);
        SSL_write(server_ssl, buffer, strlen(buffer));
        g_free(username);
		return;
    } else if (strncmp("/say", line, 4) == 0) {
        /* Skip whitespace */
        int i = 4;
        while (line[i] != '\0' && isspace(line[i])) { i++; }
        if (line[i] == '\0') {
            write(STDOUT_FILENO, "Usage: /say username message\n",
            29);
            fsync(STDOUT_FILENO);
            return;
        }
        /* Skip whitespace */
        int j = i+1;
        while (line[j] != '\0' && isgraph(line[j])) { j++; }
        if (line[j] == '\0') {
            write(STDOUT_FILENO, "Usage: /say username message\n", 29);
            fsync(STDOUT_FILENO);
            return;
        }
        char* receiver = g_strndup(&line[i], j - i);
        char* message = g_strdup(&line[j + 1]);
        snprintf(buffer, MAX_MESSAGE_SIZE, "SAY %s\r\n%s", receiver, message);
        SSL_write(server_ssl, buffer, strlen(buffer));
        g_free(receiver);
        g_free(message);
    } else if (strncmp("/user", line, 5) == 0) {
        int i = 5;
        /* Skip whitespace */
        while (line[i] != '\0' && isspace(line[i])) { i++; }
        if (line[i] == '\0') {
            write(STDOUT_FILENO, "Usage: /user username\n", 22);
            fsync(STDOUT_FILENO);
            return;
        }
        gchar* new_user = strdup(&line[i]);
        char passwd[48];
        getpasswd("Password: ", passwd, 48);
        /* Process and send this information to the server. */
        snprintf(buffer, MAX_MESSAGE_SIZE, "USER %s\r\n%s", new_user, passwd);
        SSL_write(server_ssl, buffer, strlen(buffer));

        g_free(new_user);
		return;
    } else if (strncmp("/newpass", line, 8) == 0) {
        char passwd[48];
        getpasswd("Old password: ", passwd, 48);
        char new_passwd[48];
        getpasswd("New password: ", new_passwd, 48);

        /* Process and send this information to the server. */
        snprintf(buffer, MAX_MESSAGE_SIZE, "NEWPASS %s\r\n%s\r\n%s", user, passwd, new_passwd);
        SSL_write(server_ssl, buffer, strlen(buffer));
		return;
    } else if (strncmp("/who", line, 4) == 0) {
        /* Query all available users */
        SSL_write(server_ssl, "WHO", 4);
		return;
    } else {
        /* Handle message sending to the current chat room */
        snprintf(buffer, MAX_MESSAGE_SIZE, "MSG %s", line);
        SSL_write(server_ssl, buffer, strlen(buffer));
        return;
    }
    g_free(line);
}

void setup_ssl(SSL_CTX* ssl_ctx) {
    if (ssl_ctx == NULL) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_certificate_file(ssl_ctx, CLIENT_CERTIFICATE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, CLIENT_KEY, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_check_private_key(ssl_ctx) == 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        printf("Usage %s [HOST] [PORT]\n", argv[0]);
        exit(0);
    }

    /* Parse the arguments. */
    short requested_port;
    sscanf(argv[2], "%hd", &requested_port);

    initialize_exitfd();

    /* Initialize OpenSSL */
    SSL_library_init();
    SSL_load_error_strings();
    SSL_CTX* ssl_ctx = SSL_CTX_new(TLSv1_client_method());
    setup_ssl(ssl_ctx);
    server_ssl = SSL_new(ssl_ctx);
    if (server_ssl == NULL) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* Create and bind a TCP socket */
    struct sockaddr_in server;
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        exit(errno);
    }
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    inet_pton(AF_INET, argv[1], &server.sin_addr);
    server.sin_port = htons(requested_port);
    if (connect(server_fd, (struct sockaddr *) &server, sizeof(server)) == -1) {
        perror("connect");
        exit(EXIT_FAILURE);
    }

    /* Set up secure connection to the chatd server. */
    SSL_set_fd(server_ssl, server_fd);
    if (SSL_connect(server_ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        perror("SSL_connect");
        exit(EXIT_FAILURE);
    }

    /* Read characters from the keyboard while waiting for input.
    */
    prompt = g_strdup("Lobby> ");
    chatroom = strdup("Lobby");
    rl_callback_handler_install(prompt, &readline_callback);
    for (;;) {
        fd_set rfds;
        struct timeval timeout;

        /* You must change this. Keep exitfd[0] in the read set to
        receive the message from the signal handler. Otherwise,
        the chat client can break in terrible ways. */
        FD_ZERO(&rfds);
        FD_SET(STDIN_FILENO, &rfds);
        FD_SET(exitfd[0], &rfds);
        FD_SET(server_fd, &rfds);

        timeout.tv_sec = 30;
        timeout.tv_usec = 0;

        int r = select(server_fd + 1, &rfds, NULL, NULL, &timeout);
        if (r < 0) {
            if (errno == EINTR) {
                /* This should either retry the call or
                exit the loop, depending on whether we
                received a SIGTERM. */
                continue;
            }
            /* Not interrupted, maybe nothing we can do? */
            perror("select()");
            break;
        }
        if (r == 0) {
            write(STDOUT_FILENO, "No message?\n", 12);
            fsync(STDOUT_FILENO);
            /* Whenever you print out a message, call this
            to reprint the current input line. */
            rl_forced_update_display();
            continue;
        }
        if (FD_ISSET(exitfd[0], &rfds)) {
            /* We received a signal. */
            int signum;
            for (;;) {
                if (read(exitfd[0], &signum, sizeof(signum)) == -1) {
                    if (errno == EAGAIN) {
                        break;
                    } else {
                        perror("read()");
                        exit(EXIT_FAILURE);
                    }
                }
            }
            if (signum == SIGINT) {
                /* Don't do anything. */
                printf("interrupted");
            } else if (signum == SIGTERM) {
                /* Clean-up and exit. */
                break;
            }
        }
        if (FD_ISSET(STDIN_FILENO, &rfds)) {
            rl_callback_read_char();
        }

        /* Handle messages from the server here! */
        if (FD_ISSET(server_fd, &rfds)) {
            int ssl_error, bytes_read, read_blocked;
            char buf[MAX_MESSAGE_SIZE];
            do {
                memset(buf, 0, MAX_MESSAGE_SIZE);
                read_blocked = 0;
                bytes_read = SSL_read(server_ssl, &buf, MAX_MESSAGE_SIZE);
                /* Check SSL errors */
                switch(ssl_error = SSL_get_error(server_ssl, bytes_read)) {
                    case SSL_ERROR_NONE:
                        //fprintf(stdout, "Received a message from the server with size: %d\n", bytes_read);
                        if (bytes_read == 0) {
                            break;
                        } else {
                            write(STDOUT_FILENO, buf, bytes_read);
                            write(STDOUT_FILENO, "\n", 1);
                            fsync(STDOUT_FILENO);
                        }
                        break;
                    case SSL_ERROR_ZERO_RETURN:
                    //connection closed by client, clean up
                    break;
                    case SSL_ERROR_WANT_READ:
                    //the operation did not complete, block the read
                    read_blocked = 1;
                    break;
                    case SSL_ERROR_WANT_WRITE:
                    //the operation did not complete
                    break;
                    case SSL_ERROR_SYSCALL:
                    //some I/O error occured (could be caused by false start in Chrome for instance), disconnect the client and clean up
                    break;
                    default:
                    bytes_read = 0;
                }
            } while (SSL_pending(server_ssl) && !read_blocked);
            if (bytes_read == 0) {
                fprintf(stdout, "Connection was closed by the server!\n");
                rl_callback_handler_remove();
                signal_handler(SIGTERM);
                break;
            } else if (strncmp("JOIN", buf, 4) == 0) {
                /* Result from trying to join a chatroom */
                /* The message should look like: JOIN: [chatroom] success */
                gchar** join_chatroom = g_strsplit(buf, " ", -1);
                if (join_chatroom[1] != NULL) {
                    g_free(prompt);
                    g_free(chatroom);
                    /* What should the new prompt look like? */
                    chatroom = g_strdup(join_chatroom[1]);
                    prompt = g_strdup_printf("%s(as %s)> ", chatroom, user);
                    rl_set_prompt(prompt);
                }
                g_strfreev(join_chatroom);
            } else if (strncmp("LOGIN", buf, 5) == 0) {
                /* Result from trying to login */
                /* The message should look like: LOGIN: [username] authenticated */
                gchar** login_username = g_strsplit(buf, " ", -1);
                if (login_username[1] != NULL) {
                    g_free(prompt);
                    g_free(user);
                    user = g_strdup(login_username[1]);
                    /* What should the new prompt look like? */
                    prompt = g_strdup_printf("%s(as %s)> ", chatroom, user);
                    rl_set_prompt(prompt);
                }
                g_strfreev(login_username);
            }
			rl_forced_update_display ();
        }
    }

    /* replace by code to shutdown the connection and exit
    the program. */
    fprintf(stdout, "%s\n", "Client quit gracefully");
    SSL_shutdown(server_ssl);
    SSL_free(server_ssl);
    SSL_CTX_free(ssl_ctx);
    close(server_fd);

    g_free(prompt);
    g_free(user);
    g_free(chatroom);

    /* Copy pasted OpenSSL shutdown functions */
    ERR_free_strings();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    return EXIT_SUCCESS;
}
