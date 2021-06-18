#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#define SIZE 350
#define SIZE_SMALL 100

typedef enum {
    META_COMMAND_EXIT,
    META_COMMAND_USER,
    META_COMMAND_UNRECOGNIZED_COMMAND
} MetaCommandResult;

// global var
const int PORT = 3000;
const int SIZE_BUFFER =  sizeof(char) * SIZE;
const char *cur_dir = "/home/axel/dev/fp/database/databases";
const char *USERS_TABLE = "./env/users";
const char *PERMISSION_TABLE = "./env/permission";
const char *LOG_PATH = "./env/log";


// index command & resolver
MetaCommandResult do_meta_command();
void *route();
bool auth_login();
bool create_user();
bool create_database();
bool create_table();
bool use_database();
bool grant_permission();
bool grant_db_permission_by_creating();
bool drop_database();
bool drop_table();
bool drop_column();
bool delete_from();


// Socket function
int *create_daemon();
int create_tcp_socket();


// utility
void write_log();
int get_user_id();
int get_new_id();
int check_permission();
void print_tips();
bool remove_db_content();
bool check_db_name();
bool remove_column_from_table();


int main() {
    pid_t pid, sid;
    create_daemon(&pid, &sid);

    struct sockaddr_in new_addr;
    socklen_t addr_len;
    pthread_t tid;
    int base_fd = create_tcp_socket();
    int new_fd;

    while (true) {
        new_fd = accept(base_fd, (struct sockaddr *)&new_addr, &addr_len);
        if (new_fd >= 0) {
            printf("New connection with fd: %d\n", new_fd);
            pthread_create(&tid, NULL, &route, (void *) &new_fd);
        } else {
            fprintf(stderr, "New connection failure '%s'\n", strerror(errno));
        }
    }

    return 0;

}

void *route(void *argv) {
    chdir(cur_dir);
    int fd = *(int *) argv;
    char query[SIZE], buffer[SIZE];

    while (read(fd, query, SIZE) != 0) {
        // printf("fd [%d] ", fd);
        // puts(query);
        strcpy(buffer, query);

        char *username = strtok(buffer, "#");
        char *db = strtok(NULL, "#");
        char *command = strtok(NULL, "?");
        if (command == NULL) {
            write(fd, "", SIZE_BUFFER);
            continue;
        }
        printf("\n[%s]\nuser [%s] db [%s] query [%s]\n", query, username, db, command);

        if (command[0] == '\\') {
            MetaCommandResult result = do_meta_command(fd, query, buffer);
        } else if (strstr(command, "LOGIN") != NULL) {
            auth_login(fd, query);
        } else if (strstr(command, "CREATE USER ") != NULL){
            create_user(fd, query);
            write_log(query);
        } else if (strstr(command, "GRANT PERMISSION ") != NULL) {
            grant_permission(fd, query);
            write_log(query);
        } else if(strstr(command, "CREATE DATABASE ") != NULL) {
            create_database(fd, query);
            write_log(query);
        } else if(strstr(command, "USE ") != NULL)  {
            use_database(fd, query);
            write_log(query);
        } else if(strstr(command, "CREATE TABLE ") != NULL) {
            create_table(fd, query);
            write_log(query);
        } else if(strstr(command, "DROP DATABASE ") != NULL) {
            drop_database(fd, query);
            write_log(query);
        } else if(strstr(command, "DROP TABLE ") != NULL) {
            drop_table(fd, query);
            write_log(query);
        } else if(strstr(command, "DROP COLUMN ") != NULL) {
            drop_column(fd, query);
            write_log(query);
        } else if(strstr(command, "DELETE FROM ") != NULL) {
            delete_from(fd, query);
            write_log(query);
        } else {
            print_tips(fd);
        }

        // printf("Connection terminated with fd: [%d]\n", fd);
    }

    close(fd);
}

bool auth_login(int fd, char *buffer) {
    int id = -1;
    char temp[SIZE];    
    char *username = strtok(buffer, "#");
    strtok(NULL, "#");
    char password[SIZE]; 
    if (strcmp(username, "root") == 0) {
        strcpy(password, username);
    } else {
        strtok(NULL, " ");
        strcpy(password, strtok(NULL, " "));
    }
    // printf("username [%s] password [%s]\n", username, password);

    if(strcmp(password, "root") == 0) {
        id = 0;
    } else {
        FILE* fp = fopen(USERS_TABLE, "r");
        if (fp != NULL) {
            printf("getting user id\n");
            id = get_user_id(USERS_TABLE, username, password, 1);
            fclose(fp);
        }
    }

    if (id == -1) {
        write(fd, "Invalid username or password\n", SIZE_BUFFER);
        return false;
    } else {
        sprintf(temp, "Logged in as '%s'\n", username);
        write(fd, temp, SIZE_BUFFER);
        return true;
    }
}

bool create_user(int fd, char* query) {
    FILE * fp = fopen(USERS_TABLE, "a+");
    char temp[SIZE], message[SIZE], error[SIZE];
    strcpy(temp, query);
    char *username = NULL;
    char *password = NULL;
    char *handling = NULL;
    char *access = strtok(temp, "#");
    strtok(NULL, "#");
    handling = strtok(NULL, ";");
    sprintf(error, "Unidentified command, did you mean\nCREATE USER [nama_user] IDENTIFIED BY [password_user]; ?\n");
    int i, counter =  0;
    printf("temp [%s]\n", handling);
    for (i = 0; ; i++) {
        if (handling[i] == '\0') break;
        if (handling[i] == 32) {
            counter++;
        }
    }
    printf("counter [%d]\n", counter);

    if (counter < 5) {
        write(fd, error, SIZE_BUFFER);
        return false;
    } else if (counter > 5) {
        write(fd, error, SIZE_BUFFER);
        return false;
    }

    strtok(handling, " ");
    strtok(NULL, " ");
    username = strtok(NULL, " ");
    strtok(NULL, " ");
    strtok(NULL, " ");
    password = strtok(NULL, " ");
    
    printf("query [%s]\naccess [%s] username [%s] password [%s]\n", query, access, username, password);

    // check access of currently logged in user
    if (strcmp(access, "root") != 0) {
        write(fd, "Cannot create user, should use root access\n", SIZE_BUFFER);
        return false;
    }

    for (int i = 0; ;i++) {
        if (password[i] == '\0') break;

        if (!(password[i] >= 'a' && password[i] <= 'z') && !(password[i] >= 'A' && password[i] <= 'Z')) {
            write(fd, "Password should only contain lowercase and uppercase alphabet\n", SIZE_BUFFER);
            return false;
        }
    }

    // Create new table file if fp is empty
    char check[30];
    fscanf(fp, "%s", check);
    if (strstr(check, "id,username,password") == NULL) {
        fprintf(fp, "id,username,password\n0,root,root\n");
        fclose(fp);
    }

    int id = get_user_id(USERS_TABLE, username, password, 2);
    fp = fopen(USERS_TABLE, "a");
    if (id > 0) {
        sprintf(message, "Username '%s' has been taken\n", username);
        write(fd, message, SIZE_BUFFER);
        fclose(fp);
        return false;
    } else {
        id = get_new_id(USERS_TABLE) + 1;
        printf("[%d] [%s] [%s]\n", id, username, password);
        fprintf(fp, "%d,%s,%s\n", id, username, password);
        sprintf(message, "Created '%s'\n", username);
        write(fd, message, SIZE_BUFFER);
        fclose(fp);
        return true;
    }
    
}

bool create_database(int fd, char* query) {
    char buffer[SIZE], newpath[SIZE], message[SIZE], error[SIZE];
    char* path = NULL;
    char* username = NULL;

    strcpy(buffer, query);
    username = strtok(buffer, "#");
    strtok(NULL, "#");
    strtok(NULL, " ");
    strtok(NULL, " ");
    path = strtok(NULL, ";");
    printf("username [%s] path [%s]\n", username, path);

    sprintf(error, "Unidentified command, did you mean\nCREATE DATABASE [nama_database]; ?\n");
    if (path == NULL) {
        write(fd, error, SIZE_BUFFER);
        return false;
    }

    if (strstr(path, " ") != NULL) {
        write(fd, "Database name should not contain an empty space\n", SIZE_BUFFER);
        return false;
    }

    if (strcmp(path, "env") == 0) {
        write(fd, "'env' is reserved for this sql program\n", SIZE_BUFFER);
        return false;
    }

    bool isValid = check_db_name(cur_dir, path);
    if (isValid)  {
        sprintf(newpath, "%s/%s", cur_dir, path);
        if (!mkdir(newpath, 0755)) {
            sprintf(message, "Database '%s' successfully created\n", path);
            grant_db_permission_by_creating(fd, username, path);
            write(fd, message, SIZE_BUFFER);
            return true;
        } else {
            write(fd, "An error occured please try again\n", SIZE_BUFFER);
            return false;
        }
    } else {
        sprintf(message, "Database '%s' already exist\n", path);
        write(fd, message, SIZE_BUFFER);
    }

    return true;
}

bool grant_db_permission_by_creating(int fd, char* username, char* db_name) {
    FILE * fp = fopen(PERMISSION_TABLE, "a+");

    if (strcmp(username, "root") == 0) return false;
    fprintf(fp, "%s,%s\n", username, db_name);
    fclose(fp);
    return true;
}

bool use_database(int fd, char* query) {
    char buffer[SIZE], message[SIZE], error[SIZE], newpath[SIZE];
    char* db_name;
    char* username;

    sprintf(error, "Unidentified command, did you mean\nUSE [nama_database]; ?");
    strcpy(buffer, query);

    username = strtok(buffer, "#");
    strtok(NULL, "#");
    if (strcmp(strtok(NULL, " "), "USE") != 0){
        write(fd, error, SIZE_BUFFER);
        return false;
    }
    db_name = strtok(NULL, ";");


    int permission = check_permission(username, db_name);
    int isDbExist = check_db_name(cur_dir, db_name);

    if (isDbExist) {
        sprintf(message, "Database '%s' doesn't exist'\n", db_name);
        write(fd, message, SIZE_BUFFER);
        return false;
    }

    if (strcmp(username, "root") == 0) {
        sprintf(message, "Connected to '%s'\n", db_name);
        write(fd, message, SIZE_BUFFER);
        return true;
    }

    if (!permission) {
        sprintf(message, "Connected to '%s'\n", db_name);
        write(fd, message, SIZE_BUFFER);
    } else {
        sprintf(message, "You dont have permission to '%s'\n", db_name);
        write(fd, message, SIZE_BUFFER);
        return false;
    }
    return true;
}

bool grant_permission(int fd, char* query) {
    char buffer[SIZE], message[SIZE], error[SIZE], argcheck[SIZE];
    char* db_name = NULL;
    char* target = NULL;
    char* username = NULL;
    char* handling = NULL;
    int permission, isTargetExist, spaceCount = 0;
    bool isValid;
    sprintf(error, "Unidentified command, did you mean\nGRANT PERMISSION [nama_database] INTO [nama_user]; ?\n");

    strcpy(buffer, query);
    strcpy(argcheck, query);

    strtok(argcheck, "#");
    strtok(NULL, "#");
    handling = strtok(NULL, ";");
    puts(handling);
    int i;
    for (i = 0; ; i++) {
        if (handling[i] == '\0') break;
        if (handling[i] == 32) {
            // printf("space\n");
            spaceCount++;
        }
    }

    if (spaceCount != 4) {
        write(fd, error, SIZE_BUFFER);
        return false;
    }


    username = strtok(buffer, "#");
    strtok(NULL, "#");
    strtok(NULL, " ");
    strtok(NULL, " ");
    db_name = strtok(NULL, " ");
    if (strcmp(strtok(NULL, " "), "INTO") != 0){
        write(fd, error, SIZE_BUFFER);
        return false;
    }
    target = strtok(NULL, ";");
    
    printf("access [%s] db [%s] target [%s]\n", username, db_name, target);
    if (strcmp(username, "root") != 0) {
        write(fd, "Cannot grant permission, should use root access\n", SIZE_BUFFER);
        return false;
    }

    if (strcmp(db_name, "env") == 0) {
        write(fd, "Cannot grant permission to reserved database 'env'\n", SIZE_BUFFER);
        return false;
    }

    isTargetExist = get_user_id(USERS_TABLE, target, " ", 2);
    if (isTargetExist == -1) {
        sprintf(message, "User '%s' doesn't exist\n", target);
        write(fd, message, SIZE_BUFFER);
        return false;
    }

    FILE * fp = fopen(PERMISSION_TABLE, "r");

    if (fp == NULL) {
        fp = fopen(PERMISSION_TABLE, "a+");
        fprintf(fp, "username,database\n");
    }

    isValid = check_db_name(cur_dir, db_name);
    permission = check_permission(target, db_name);
    printf("permission [%d]\n", permission);
    if (permission && !isValid) {
        fprintf(fp, "%s,%s\n", target, db_name);
        write(fd, "Permission granted\n", SIZE_BUFFER);
    } else if (isValid) {
        sprintf(message, "Database '%s' doesn't exist\n", db_name);
        write(fd, message, SIZE_BUFFER);
    } else {
        sprintf(message, "User '%s' already have permission\n", target);
        write(fd, message, SIZE_BUFFER);
    }
    fclose(fp);
    return true;
}

bool create_table(int fd, char* query) {
    char buffer[SIZE], message[SIZE], error[SIZE], result[SIZE], type[SIZE],path[SIZE_SMALL];
    char* username = NULL;
    char* db_name = NULL;
    char* table_name = NULL;
    char* column = NULL;

    strcpy(message, "You are currently not connected to any databases\n");
    strcpy(buffer, query);
    username = strtok(buffer, "#");
    db_name = strtok(NULL, "#");
    strtok(NULL, " ");
    strtok(NULL, " ");
    table_name = strtok(NULL, " ");

    if (strcmp(db_name, "-") == 0) {
        write(fd, message, SIZE_BUFFER);
        return false;
    }

    if (strstr(table_name, " ") != NULL) {
        write(fd, "Table name should not contain empty space\n", SIZE_BUFFER);
        return false;
    }

    sprintf(path, "%s/%s/%s", cur_dir, db_name, table_name);
    printf("table path [%s]\n", path);

    FILE *fp = fopen(path, "r");
    if (fp != NULL) {
        sprintf(error, "Table '%s' is already exist\n", table_name);
        write(fd, error, SIZE_BUFFER);
        return false;
    }

    column = strtok(NULL, ";");
    printf("%s\n", column);

    int i = 0, j = 0, k = 0;
    bool flag = true;
    for (i = 1; ;i++) {
        if (column[i] == 41) break;
        if (column[i] == 32) {
            flag = !flag;
            if (flag) {
                result[j] = ',';
                j++;
                continue;
            } else {
                continue;
            }
        }
        if (flag) {
            result[j] = column[i];
            j++;
        } else {
            type[k] = column[i];
            k++;
        }
    }

    result[j] = '\0';
    type[k] = '\0';
    printf("result [%s] type[%s]\n", result, type);
    
    fp = fopen(path, "w+");
    fprintf(fp, "%s\n%s\n", result, type);
    fclose(fp);
    write(fd, "Table created\n", SIZE_BUFFER);
    return true;
}

bool drop_database(int fd, char* query) {
    char buffer[SIZE], message[SIZE], error[SIZE], result[SIZE], path[SIZE_SMALL];
    char* username = NULL;
    char* db_name = NULL;
    char* connection = NULL;

    strcpy(buffer, query);
    username = strtok(buffer, "#");
    connection = strtok(NULL, "#");
    strtok(NULL, " ");
    strtok(NULL, " ");
    db_name = strtok(NULL, ";");

    if (check_db_name(cur_dir, db_name)) {
        write(fd, "Database doesn't exist\n'", SIZE_BUFFER);
        return false;
    }

    sprintf(path, "%s/%s", cur_dir, db_name);
    printf("db [%s] path [%s]\n", db_name, path);

    remove_db_content(path);
    rmdir(path);
    if (strcmp(connection, db_name) == 0) {
        sprintf(message, "Connected to '-'\nDatabase '%s' dropped\n", db_name);
    } else {
        sprintf(message, "Database  '%s' dropped\n", db_name);
    }

    write(fd, message, SIZE_BUFFER);
    return true;
}

bool drop_table(int fd, char* query) {
    char buffer[SIZE], message[SIZE], error[SIZE], result[SIZE], path[SIZE_SMALL];
    char* username = NULL;
    char* db_name = NULL;
    char* table_name = NULL;

    strcpy(buffer, query);
    username = strtok(buffer, "#");
    db_name = strtok(NULL, "#");
    strtok(NULL, " ");
    strtok(NULL, " ");
    table_name = strtok(NULL, ";");

    sprintf(path, "%s/%s/%s", cur_dir, db_name, table_name);
    printf("db [%s] table [%s]\npath [%s]\n", db_name, table_name, path);

    if (strcmp(db_name, "-") == 0) {
        write(fd, "You are currently not connected to any databases\n", SIZE_BUFFER);
        return false;
    }

    FILE * fp = fopen(path, "r");
    if (fp == NULL) {
        write(fd, "Table doesn't exist\n", SIZE_BUFFER);
        return false;
    }
    
    remove(path);
    write(fd, "Table dropped\n", SIZE_BUFFER);
    return true;
}

bool drop_column(int fd, char* query) {
    char buffer[SIZE], message[SIZE], error[SIZE], result[SIZE], argcheck[SIZE], path[SIZE_SMALL];
    char* username = NULL;
    char* db_name = NULL;
    char* table_name = NULL;
    char* column_name = NULL;
    char* handling = NULL;

    strcpy(argcheck, query);
    strtok(argcheck, "#");
    strtok(NULL, "#");
    handling = strtok(NULL, ";");
    puts(handling);
    int i, spaceCount = 0;
    for (i = 0; ; i++) {
        if (handling[i] == '\0') break;
        if (handling[i] == 32) {
            // printf("space\n");
            spaceCount++;
        }
    }

    sprintf(error, "Unidentified command, did you mean\nDROP COLUMN [column_name] FROM [table_name]; ?\n");

    if (spaceCount != 4) {
        write(fd, error, SIZE_BUFFER);
        return false;
    }

    strcpy(buffer, query);
    username = strtok(buffer, "#");
    db_name = strtok(NULL, "#");

    if (strcmp(db_name, "-") == 0) {
        write(fd, "You are currently not connected to any databases\n", SIZE_BUFFER);
        return false;
    }

    strtok(NULL, " ");
    strtok(NULL, " ");
    column_name = strtok(NULL, " ");
    if (strcmp(strtok(NULL, " "), "FROM") != 0) {
        write(fd, error, SIZE_BUFFER);
        return false;
    }
    table_name = strtok(NULL, ";");
    sprintf(path, "%s/%s/%s", cur_dir, db_name, table_name);
    printf("db [%s] table[%s]\n", db_name, table_name);
    printf("path [%s]\n", path);
    FILE * fp = fopen(path, "r");

    if (fp == NULL) {
        sprintf(message, "Table '%s' doesn't exist\n'", table_name);
        write(fd, message, SIZE_BUFFER);
        return false;
    }
    int res = remove_column_from_table(path, db_name, column_name);

    if (!res) {
        write(fd, "Column doesn't exist\n'", SIZE_BUFFER);
        return false;
    }

    sprintf(message, "Column '%s' dropped\n", column_name);
    write(fd, message, SIZE_BUFFER);
    return true;
}

bool check_db_name(char* param_path, char* db_name) {
    DIR *dir = opendir(param_path);
    struct dirent *dp;

    if (!dir) return false;

    // list file recursive
    while ((dp = readdir(dir)) != NULL) {
        if (strcmp(dp->d_name, ".") != 0 && strcmp(dp->d_name, "..") != 0) {
            printf("db [%s]\n", dp->d_name);
            if (strcmp(db_name, dp->d_name) == 0) {
                return false;
            }
        }
    }

    return true;
}

bool remove_db_content(char* param_path) {
    DIR *dir = opendir(param_path);
    struct dirent *dp;
    char new_path[SIZE];

    if (!dir) return false;

    while ((dp = readdir(dir)) != NULL) {
        if (strcmp(dp->d_name, ".") != 0 && strcmp(dp->d_name, "..") != 0) {
            memset(new_path, 0, SIZE_BUFFER);
            sprintf(new_path, "%s/%s", param_path, dp->d_name);
            printf("path [%s]\n", new_path);
            remove(new_path);
        }
    }
    return true;
}

bool remove_column_from_table(char *param_path, char* db_name, char* column_name) {
    char db[SIZE], input[SIZE], new_path[SIZE], buffer[SIZE];
    char *temp = NULL;
    char *point = NULL;
    int order = 0, flag = 0, counter = 0;
    sprintf(new_path, "%s/%s/(((", cur_dir, db_name);
    FILE *fp = fopen(param_path, "r");
    FILE *fp_clone = fopen(new_path, "a+");

    fscanf(fp, "%s", db);
    printf("[%s]\n", db);
    strcpy(buffer, db);
    temp = strtok(buffer,",");
    printf("%s\n", temp);
    while (temp != NULL) {
        if (strcmp(column_name, temp) == 0) {
            flag = 1;
            break;
        }
        temp = strtok(NULL, ",");
        order++;
    }
    // printf("order [%d]\n", order);
    if (!flag) {
        fclose(fp);
        fclose(fp_clone);
        return false;
    }

    fp = fopen(param_path, "r");
    while (fscanf(fp, "%s", db) != EOF) {
        counter = 0;
        memset(input, 0, SIZE_BUFFER);
        memset(buffer, 0, SIZE_BUFFER);
        strcpy(buffer, db);
        temp = strtok(buffer, ",");
        while (temp != NULL) {
            if (counter == order){
                counter++;
                temp = strtok(NULL, ",");
                continue;    
            }
            // printf("counter [%d] temp [%s]\n", counter, temp);
            strcat(input, temp);
            strcat(input, ",");
            temp = strtok(NULL, ",");
            counter++;
        }
        
        int len = strlen(input);
        input[len - 1] = '\0';
        printf("db [%s] input [%s]\n", db, input);
        fprintf(fp_clone, "%s\n", input);
    }
    fclose(fp);
    fclose(fp_clone);
    remove(param_path);

    fp = fopen(param_path, "a+");
    fp_clone = fopen(new_path, "r");
    while (fscanf(fp_clone, "%s", db) != EOF) {
        fprintf(fp, "%s\n", db);
    }
    fclose(fp);
    fclose(fp_clone);
    remove(new_path);
    return true;
}

bool delete_from(int fd, char* query) {
    char buffer[SIZE], message[SIZE], error[SIZE], input[SIZE], new_path[SIZE], path[SIZE_SMALL];
    char* username = NULL;
    char* db_name = NULL;
    char* table_name = NULL;

    strcpy(buffer, query);
    sprintf(error, "Unidentified command, did you mean\nDELETE FROM [nama_tabel]; ?\n");

    username = strtok(buffer, "#");
    db_name = strtok(NULL, "#");

    if (strcmp(db_name, "-") == 0) {
        write(fd, "You are currently not connected to any databases\n", SIZE_BUFFER);
        return false;
    }
    strtok(NULL, " ");
    strtok(NULL, " ");
    table_name = strtok(NULL, ";");

    sprintf(path, "%s/%s/%s", cur_dir, db_name, table_name);
    printf("path [%s]\n", path);

    FILE* fp = fopen(path, "r");;
    if (fp == NULL) {
        sprintf(message, "Table '%s' doesn't exist\n", table_name);
        write(fd, message, SIZE_BUFFER);
        return false;
    }

    sprintf(new_path, "%s/%s/(((", cur_dir, db_name);

    fp = fopen(path, "r");
    FILE *fp_clone = fopen(new_path, "a+");

    fscanf(fp, "%s", input);
    fprintf(fp_clone, "%s\n", input);
    fscanf(fp, "%s", input);
    fprintf(fp_clone, "%s\n", input);
    fclose(fp);
    fclose(fp_clone);
    remove(path);

    fp = fopen(path ,"a+");
    fp_clone = fopen(new_path, "r");
    fscanf(fp_clone, "%s", input);
    fprintf(fp, "%s\n", input);
    fscanf(fp_clone, "%s", input);
    fprintf(fp, "%s\n", input);
    fclose(fp);
    fclose(fp_clone);
    remove(new_path);
    
    write(fd, "Table truncated\n", SIZE_BUFFER);
    return true;
}

int get_user_id(char *path, char *username, char *password, int option) {
    int id = -1;
    char db[SIZE], input[SIZE];
    FILE *fp = fopen(path, "r");

    if (fp == NULL) return -1;
    
    if (option == 1) {
        sprintf(input, "%s,%s", username, password);

        while (fscanf(fp, "%s", db) != EOF) {
            char *temp = strstr(db, ",") + 1;

            printf("db [%s] temp [%s] input[%s]\n", db, temp, input);
            if (strcmp(temp, input) == 0) {
                id = atoi(strtok(db, ","));
                break;
            }
        }
    } else {
        sprintf(input, "%s", username);

        while (fscanf(fp, "%s", db) != EOF) {
            char *temp = strstr(db, ",") + 1;
            temp = strtok(temp, ",");

            printf("db [%s] temp [%s] input[%s]\n", db, temp, input);
            if (strcmp(temp, input) == 0) {
                id = atoi(strtok(db, ","));
                printf("id %d\n", id);
                break;
            }
        }
    }

    fclose(fp);

    return id;
}

int get_new_id(char* path) {
    int id = 1;
    FILE *fp = fopen(path, "r");
    char db[SIZE];

    if (fp == NULL) return -1;

    while (fscanf(fp, "%s", db) != EOF) {
        id = atoi(strtok(db, ","));
    }
    return id;
}

int check_permission(char *username, char* db_name) {
    int permission = 1;
    char readln[SIZE], input[SIZE];
    FILE *fp = fopen(PERMISSION_TABLE, "r");

    if (fp == NULL) return -1;

    sprintf(input, "%s,%s", username, db_name);

    while (fscanf(fp, "%s", readln) != EOF) {
        printf("readl [%s] input[%s]\n", readln, input);
        if (strcmp(readln, input) == 0) {
            permission = 0;
            break;
        }
    }
    return permission;
}

void write_log(char* query) {
    char clock[SIZE_SMALL], date[SIZE_SMALL], res[SIZE], buffer[SIZE];
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    char* username = NULL;
    char* command = NULL;

    strcpy(buffer, query);
    username = strtok(buffer, "#");
    strtok(NULL, "#");
    command = strtok(NULL, ";");

    sprintf(clock, "%02d:%02d:%02d", tm.tm_hour, tm.tm_min, tm.tm_sec);
    sprintf(date, "%04d-%02d-%02d", tm.tm_year + 1900, tm.tm_mon, tm.tm_mday);
    sprintf(res, "%s %s:%s:%s", date, clock, username, command);

    FILE* fp = fopen(LOG_PATH, "a+");
    fprintf(fp, "%s\n", res);
    fclose(fp);
}

MetaCommandResult do_meta_command(int fd, char* input_buffer, char* result) {

    char temp[SIZE];
    char *user = strtok(input_buffer, "#");
    char *db = strtok(NULL, "#");
    char *command = strtok(NULL, "?");
    // puts("Meta command");
    // printf("user [%s] command [%s]\n", user, command);

    if (strcmp(command, "\\exit") == 0) {
        write(fd, "Exited\n", SIZE_BUFFER);
        return META_COMMAND_EXIT;
    } else if (strcmp(command, "\\user") == 0) {
        sprintf(temp, "Logged in as '%s'\n", user);
        write(fd, temp, SIZE_BUFFER);
        return META_COMMAND_USER;
    } else if (strcmp(command, "\\db") == 0) {
        if (strcmp(db, "-") == 0) {
            sprintf(temp, "You are currently not connected to any databases\n");
        } else {
            sprintf(temp, "Connected to database '%s'\n", db);
        }
        
        write(fd, temp, SIZE_BUFFER);
    } else if (strcmp(command, "\\help") == 0){
        sprintf(temp, "=== Meta Command List ===\n\\help\n\\exit\n\\user\n\\db\n");
        write(fd, temp, SIZE_BUFFER);
    } else {
        print_tips(fd);
        return META_COMMAND_UNRECOGNIZED_COMMAND;
    }
}

int create_tcp_socket() {
    struct sockaddr_in sockaddr;
    int fd, ret_val;
    int opt = 1;

    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (fd == -1) {
        fprintf(stderr, "socket creation failure '%s'\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    printf("Socket create with fd:  %d\n", fd);

    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(PORT);
    sockaddr.sin_addr.s_addr = INADDR_ANY;

    ret_val = bind(fd, (struct sockaddr *)&sockaddr, sizeof(struct sockaddr_in));
    if (ret_val != 0) {
        fprintf(stderr, "bind socket failure '%s'\n", strerror(errno));
        close(fd);
        exit(EXIT_FAILURE);
    }

    ret_val = listen(fd, 5);
    if  (ret_val != 0) {
        fprintf(stderr, "listen failure '%s'\n", strerror(errno));
        close(fd);
        exit(EXIT_FAILURE);
    }

    return fd;
}

void print_tips(int fd) {
    write(fd, "Unrecognized command\nTry running '\\help'\n", SIZE_BUFFER);
}

int *create_daemon(pid_t *pid, pid_t *sid) {
    *pid = fork();

    if (*pid != 0) {
        exit(EXIT_FAILURE);
    }
    if (*pid > 0) {
        exit(EXIT_SUCCESS);
    }

    umask(0);

    *sid = setsid();

    if (*sid < 0 || chdir(cur_dir) < 0) {
        exit(EXIT_FAILURE);
    }
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
}