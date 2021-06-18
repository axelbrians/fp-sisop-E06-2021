#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <netdb.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#define SIZE 350

// global var
const int PORT = 3000;
const int SIZE_BUFFER =  sizeof(char) * SIZE;
bool wait = false;
char user[SIZE] = {0};
char db[SIZE] = "-";
char auth[10];


struct InputBuffer_t {
    char* buffer;
    size_t buffer_length;
    ssize_t input_length;
};

typedef struct InputBuffer_t InputBuffer;

typedef enum {
    META_COMMAND_SUCCESS,
    META_COMMAND_UNRECOGNIZED_COMMAND
} MetaCommandResult;

typedef enum {
    PREPARE_SUCCESS,
    PREPARE_UNRECOGNIZED_STATEMENT
} PrepareResult;

typedef enum {
    STATEMENT_INSERT,
    STATEMENT_SELECT
} StatementType;

typedef struct {
    StatementType type;
} Statement;


// repl function
InputBuffer* new_input_buffer();
MetaCommandResult do_meta_command();
PrepareResult prepare_statement();
void read_input();
bool auth_login();


// utility function
void print_prompt();


// socket
int create_tcp_socket_client();
void *input_handler();
void *output_handler();
void receive_output();
void change_db_connection();


int main(int argc, char* argv[]) {
    pthread_t tid[3];
    int client_fd = create_tcp_socket_client();

    if(!auth_login(client_fd, argc, argv)){
        exit(EXIT_FAILURE);
    }

    change_db_connection("-");
    pthread_create(&(tid[0]), NULL, &output_handler, (void *) &client_fd);
    pthread_create(&(tid[1]), NULL, &input_handler, (void *) &client_fd);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);

    close(client_fd);
    return 0;
}


InputBuffer* new_input_buffer() {
    InputBuffer* input_buffer = malloc(sizeof(InputBuffer));
    input_buffer->buffer = NULL;
    input_buffer->buffer_length = 0;
    input_buffer->input_length = 0;

    return input_buffer;
}

void read_input(InputBuffer* input_buffer) {
    ssize_t bytes_read = 
        getline(&(input_buffer->buffer), &(input_buffer->buffer_length), stdin);

    if (bytes_read <= 0) {
        printf("Error when reading input\n");
        exit(EXIT_FAILURE);
    }

    input_buffer->input_length = bytes_read - 1;
    input_buffer->buffer[bytes_read - 1] = 0;
}


bool auth_login(int  fd, int argc, char* argv[]) {
    char buffer[SIZE];

    if (geteuid() == 0) {
        write(fd, "root#-#LOGIN", SIZE_BUFFER);
        strcpy(user, "root");
        strcpy(auth, "root");
    } else if (argc == 5  
        && strcmp(argv[1], "-u") == 0
        && strcmp(argv[3], "-p") == 0
    ) {
        sprintf(buffer, "%s#-#LOGIN %s", argv[2], argv[4]);
        write(fd, buffer, SIZE_BUFFER);
        strcpy(user, argv[2]);
        strcpy(auth, "user");
    } else {
        puts("Invalid argument, './[program] -u [username] -p [password]'");
        return false;
    }

    read(fd, buffer, SIZE_BUFFER);
    puts(buffer);
    return strncmp(buffer, "Logged in\n", 9) == 0;
}

void *input_handler(void *client_fd) {
    InputBuffer* input_buffer = new_input_buffer();
    int fd = *(int *) client_fd;

    while (true) {
        if (wait) continue;
        print_prompt();
        read_input(input_buffer);

        char temp[SIZE];
        sprintf(temp, "%s#%s#%s", user, db, input_buffer->buffer);
        // printf("fd [%d] ", fd);
        // puts(temp);
        write(fd, temp, SIZE_BUFFER);
        wait = true;
    }

}

void *output_handler(void *client_fd) {
    char input_buffer[SIZE];
    int fd = *(int *) client_fd;

    while (true) {
        memset(input_buffer, 0, SIZE_BUFFER);
        receive_output(fd, input_buffer);
        printf("%s", input_buffer);
        if (strcmp(input_buffer, "Exited\n") == 0) {
            exit(EXIT_SUCCESS);
        } else if (strncmp(input_buffer, "Connected", 9) == 0) {
            char *new_db;
            strtok(input_buffer, "'");
            new_db = strtok(NULL, "'");
            change_db_connection(new_db);
        }
        fflush(stdout);
        wait = false;
    }
}

void receive_output(int fd, char* input_buffer) {
    if (recv(fd, input_buffer, SIZE, 0) == 0) {
        printf("Disconnected from server\n");
        exit(EXIT_SUCCESS);
    }
}

void change_db_connection(char *new_db) {
    memset(db, 0, SIZE_BUFFER);
    strcpy(db, new_db);
}

int create_tcp_socket_client() {
    struct sockaddr_in saddr;
    int fd, ret_val;
    int opt = 1;
    struct hostent *local_host;

    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == -1) {
        fprintf(stderr, "socket failed [%s]\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    printf("Socket created with fd: %d\n", fd);
 

    local_host = gethostbyname("127.0.0.1");
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(PORT);
    saddr.sin_addr = *((struct in_addr *)local_host->h_addr);


    ret_val = connect(fd, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));
    if (ret_val == -1) {
        fprintf(stderr, "connect failure '%s'\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    return fd;
}

void print_prompt() {
    printf("# ");
}