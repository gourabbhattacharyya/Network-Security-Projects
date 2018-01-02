#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#define BUF_SIZE 2048 * 2048
#define IVSIZE 8

typedef enum { false, true } boolean;

typedef struct {
    int sock;
    struct sockaddr address;
    struct sockaddr_in sshaddr;
    int addr_len;
    const char *key;
} connection_t;


struct ctr_state {
    unsigned char ivec[AES_BLOCK_SIZE];
    unsigned int num;
    unsigned char ecount[AES_BLOCK_SIZE];
};



int init_ctr(struct ctr_state *state, const unsigned char iv[IVSIZE]) {
    // aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the first call.
    state->num = 0;
    memset(state->ecount, 0, AES_BLOCK_SIZE);
    
    /* Initialise counter in 'ivec' to 0 */
    memset(state->ivec + IVSIZE, 0, IVSIZE);
    
    /* Copy IV into 'ivec' */
    memcpy(state->ivec, iv, IVSIZE);
}



char* read_file(const char* filename) {
    
    long int size = 0;
    char *result;
    FILE *file = fopen(filename, "r");
    
    if (!file) {
        fprintf(stderr, "Open error for key file\n");
        return NULL;
    }
    
    fseek(file, 0, SEEK_END);
    size = ftell(file);
    rewind(file);
    
    result = (char *) malloc(size);
    
    if (!result) {
        fprintf(stderr, "Memory error for key allocation\n");
        return NULL;
    }
    
    if (fread(result, 1, size, file) != size) {
        fprintf(stderr, "Read error in key file\n");
        return NULL;
    }
    
    fclose(file);
    return result;
}



//call the server process
void* server_thread(void* ptr) {
    if (!ptr)
        pthread_exit(0);
    
    //fprintf(stderr, "New client thread started\n");
    
    char buffer[BUF_SIZE];
    int ssh_fd, n;
    boolean ssh_done = false;
    struct ctr_state state;
    AES_KEY aes_key;
    unsigned char iv[IVSIZE];
    int flags;
    bzero(buffer, BUF_SIZE);
    connection_t *conn = (connection_t *)ptr;
    
    
    ssh_fd = socket(AF_INET, SOCK_STREAM, 0);               //create socket
    
    if (ssh_fd < 0) {
        int count = 0;
        while (count != 100) {
            ssh_fd = socket(AF_INET, SOCK_STREAM, 0);
            if (ssh_fd >= 0)
                break;
            count++;
        }
        
        if (ssh_fd < 0) {
            fprintf(stderr, "Socket creation error at server thread!!!\n");
            pthread_exit(0);
        }
        
    }
    
    if (connect(ssh_fd, (struct sockaddr *)&conn->sshaddr, sizeof(conn->sshaddr)) == -1) {
        fprintf(stderr, "Connection to ssh failed! Try Again!!!\n");
        pthread_exit(0);
    }
    else {
        fprintf(stderr, "Connection to ssh established Successfully!\n");
    }
    
    
    flags = fcntl(conn->sock, F_GETFL);
    if (flags == -1) {
        fprintf(stderr, "read sock 1 flag error!\n");
        fprintf(stderr, "Closing connections and exit thread!\n");
        close(conn->sock);
        close(ssh_fd);
        free(conn);
        pthread_exit(0);
    }
    
    fcntl(conn->sock, F_SETFL, flags | O_NONBLOCK);
    
    flags = fcntl(ssh_fd, F_GETFL);
    if (flags == -1) {
        fprintf(stderr, "Error reading ssh_fd flag!\n");
        close(conn->sock);
        close(ssh_fd);
        free(conn);
        pthread_exit(0);
    }
    
    fcntl(ssh_fd, F_SETFL, flags | O_NONBLOCK);
    
    //memset(buffer, 0, sizeof(buffer));
    
    
    if (AES_set_encrypt_key(conn->key, 128, &aes_key) < 0) {
        fprintf(stderr, "Encryption key error!\n");
        exit(1);
    }
    
    while (true) {
        while ((n = read(conn->sock, buffer, BUF_SIZE)) >= 0) {              //Read from socket for connection
            int count = 0;
            
            if (n == 0) {
                n = -1;
                while (count != 1000) { //count != 10
                    n = read(conn->sock, buffer, BUF_SIZE);
                    //fprintf(stderr, "Here");
                    if (n > 0)
                        break;
                    count++;
                }
                
                if (n == 0) {
                    
                    fprintf(stderr, "Server relay thread exiting...!!!\n");
                    close(conn->sock);
                    close(ssh_fd);
                    free(conn);
                    pthread_exit(0);
                    
                }
            }
            
            if (n > 0) {
                
                if (n < 8) {
                    fprintf(stderr, "Packet length smaller than 8!\n");
                    close(conn->sock);
                    close(ssh_fd);
                    free(conn);
                    pthread_exit(0);
                }
                
                memcpy(iv, buffer, IVSIZE);
                
                unsigned char *decryption = (unsigned char*)malloc((n-IVSIZE));
                //memset(decryption, 0, sizeof(decryption));
                init_ctr(&state, iv);
                
                AES_ctr128_encrypt(buffer+IVSIZE, decryption, (n-IVSIZE), &aes_key, state.ivec, state.ecount, &state.num);
                
                //write(ssh_fd, decryption, (ssize_t)(n-IVSIZE));
                while(write(ssh_fd, decryption, (ssize_t)(n-IVSIZE)) == -1) {
                    fprintf(stderr, "Write failed %zd \n", write(ssh_fd, decryption, (ssize_t)(n-IVSIZE)));
                }
                
                free(decryption);
            }
            
            if (n < BUF_SIZE)
                break;
        };
        
        //fprintf(stderr, "1---Here\n");
        while ((n = read(ssh_fd, buffer, BUF_SIZE)) >= 0) {                 //Read from socket for SSH details
            int count = 0;
            if (n == 0) {
                n = -1;
                while (count != 1000) { //count != 10
                    n = read(ssh_fd, buffer, BUF_SIZE);
                    //fprintf(stderr, "Here");
                    if (n > 0)
                        break;
                    count++;
                }
                
                if (n == 0) {
                    
                    /*
                    fprintf(stderr, "Server relay thread exiting...!!!\n");
                    close(conn->sock);
                    close(ssh_fd);
                    free(conn);
                    pthread_exit(0);
                    */
                    
                    if (ssh_done == false)
                        ssh_done = true;
                }
            }
            
            if (n > 0) {
                if(!RAND_bytes(iv, IVSIZE)) {
                    fprintf(stderr, "Error generating random bytes for IV.\n");
                    exit(1);
                }
                char *tmp = (char*)malloc((n + IVSIZE));
                memcpy(tmp, iv, IVSIZE);
                
                unsigned char encryption[n];
                memset(encryption, 0, sizeof(encryption));
                
                init_ctr(&state, iv);
                AES_ctr128_encrypt(buffer, encryption, n, &aes_key, state.ivec, state.ecount, &state.num);
                memcpy(tmp + IVSIZE, encryption, n);
                usleep(2000);
                
                //write(conn->sock, tmp, (ssize_t)(n + IVSIZE));
                
                while(write(conn->sock, tmp, (ssize_t)(n + IVSIZE)) == -1) {
                    fprintf(stderr, "Write failed %zd \n", write(conn->sock, tmp, (ssize_t)(n + IVSIZE)));
                }
                free(tmp);
            }
            
            //if (ssh_done == false && n == 0)
            //ssh_done = true;
            
            if (n < BUF_SIZE)
                break;
        }
        
        if (ssh_done)
            break;
    }
    //fprintf(stderr, "2---Here\n");
    /*
     fprintf(stderr, "Could not read SSH details... Please try again!\n");
     */
    close(conn->sock);
    close(ssh_fd);
    free(conn);
    //free(buffer);
    pthread_exit(0);
    
}




int main(int argc, char *argv[]) {
    
    char *str_listen_port = NULL;       //define listening port
    boolean server_mode = false;        //define server mode
    char *key_file = NULL;              //define key file character set
    char *str_dst = NULL;               //define destination host
    char *str_dst_port = NULL;          //define destination port
    int dst_port;                       //dest port value
    struct hostent *nlp_host;           //resolve host name
    struct sockaddr_in servaddr, sshaddr;       //socketaddress and ssh address
    
    
    if (argc > 1) {
        for (int i = 2; i <= argc; i++) {
            /* determine commandline input */
            if(strcmp(argv[i-1], "-l") == 0){
                str_listen_port = argv[(i)];
                server_mode = true;
                i++;
            }else if (strcmp(argv[i-1], "-k") == 0){
                key_file = argv[(i)];
                i++;
            }
            else {
                str_dst = argv[(i - 1)];
                str_dst_port = argv[i];
                i++;
            }
        }
    }
    else if (argc == 1) {           //if less number of arguments passed
        fprintf(stderr, "error: unrecognized command-line options given\n\n");
        exit(EXIT_FAILURE);
    }
    
    
    //check for null values
    if (server_mode == true) {
        
        if (str_listen_port == '\0' || str_listen_port == NULL) {
            
            fprintf(stderr, "Please specify port number to listen!\n");
            return 0;
        }
    }
    
    if (key_file == '\0' || key_file == NULL) {
        
        fprintf(stderr, "Please specify key file to use!\n");
        return 0;
    }
    
    
    if ((str_dst == '\0' || str_dst == NULL) || (str_dst_port == '\0' || str_dst_port == NULL)) {
        
        fprintf(stderr, "Incorrect destination and port arguments. Exiting...\n");
        return 0;
    }
    
    if (key_file == NULL) {
        fprintf(stderr, "Key file not specified!\n");
        return 0;
    }
    
    
    fprintf(stderr, "\nInitializing pbproxy using following parameters for PbProxy by Gourab Bhattacharyya_170048888:\n ServerMode: %s\n ListeningPort: %s\n KeyFile: %s\n Destination: %s\n DestinationPort: %s\n\n\n", server_mode ? "true" : "false", str_listen_port, key_file, str_dst, str_dst_port);
    
    unsigned const char *key = read_file(key_file);
    if (!key) {
        fprintf(stderr, "Read key file failed!\n");
        return 0;
    }
    
    
    
    dst_port = (int)strtol(str_dst_port, NULL, 10);
    
    if ((nlp_host=gethostbyname(str_dst)) == 0) {
        fprintf(stderr, "Resolve Error!\n");
        return 0;
    }
    
    
    
    bzero(&servaddr, sizeof(servaddr));
    bzero(&servaddr, sizeof(sshaddr));
    
    
    if (server_mode == true) {              // pbproxy running in server mode
        connection_t *connection;
        pthread_t thread;
        int listen_fd;
        int listen_port = (int)strtol(str_listen_port, NULL, 10);
        
        listen_fd = socket(AF_INET, SOCK_STREAM, 0);                //create socket for TCP connection
        
        if (listen_fd < 0) {
            int count = 0;
            while (count != 100) {
                listen_fd = socket(AF_INET, SOCK_STREAM, 0);
                if (listen_fd >= 0)
                    break;
                count++;
            }
            
            if (listen_fd < 0) {
                fprintf(stderr, "Socket creation error at server!!!\n");
                return 0;
            }
            
        }
        
        servaddr.sin_family = AF_INET;
        servaddr.sin_addr.s_addr = htons(INADDR_ANY);
        servaddr.sin_port = htons(listen_port);
        
        sshaddr.sin_family = AF_INET;
        sshaddr.sin_port = htons(dst_port);
        sshaddr.sin_addr.s_addr = ((struct in_addr *)(nlp_host->h_addr))->s_addr;
        
        bind(listen_fd, (struct sockaddr *)&servaddr, sizeof(servaddr));
        
        if (listen(listen_fd, 10) < 0) {
            fprintf(stderr, "Attempting to listen failed!\n");
            return 0;
        };
        
        while (true) {
            connection = (connection_t *)malloc(sizeof(connection_t));      //create a new connection object
            connection->sock = accept(listen_fd, &connection->address, &connection->addr_len);      //read from listening port
            if (connection->sock > 0) {
                connection->sshaddr = sshaddr;
                connection->key = key;
                pthread_create(&thread, 0, server_thread, (void*)connection);
                pthread_detach(thread);
            } else {
                free(connection);
            }
        };
        
    }
    
    else {            // pbproxy running in client mode
        
        int sockfd, n;
        char buffer[BUF_SIZE];
        struct ctr_state state;
        unsigned char iv[IVSIZE];
        AES_KEY aes_key;
        
        sockfd = socket(AF_INET, SOCK_STREAM, 0);           //create socket for TCP
        if (sockfd < 0) {
            int count = 0;
            while (count != 100) {
                sockfd = socket(AF_INET, SOCK_STREAM, 0);
                if (sockfd >= 0)
                    break;
                count++;
            }
            
            if (sockfd < 0) {
                fprintf(stderr, "Socket creation error at client!!!\n");
                return 0;
            }
            
        }
        
        
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(dst_port);
        
        servaddr.sin_addr.s_addr = ((struct in_addr *)(nlp_host->h_addr))->s_addr;
        
        if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1) {
            fprintf(stderr, "Connection failed!\n");
            return 0;
        }
        
        fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
        fcntl(sockfd, F_SETFL, O_NONBLOCK);
        bzero(buffer, BUF_SIZE);
        
        
        if (AES_set_encrypt_key(key, 128, &aes_key) < 0) {
            fprintf(stderr, "Encryption key error!\n");
            exit(1);
        }
        
        while(true) {
            while ((n = read(STDIN_FILENO, buffer, BUF_SIZE)) >= 0) {            //Read from stdin
                int count = 0;
                
                if (n == 0) {
                    n = -1;
                    while (count != 1000) { //count != 10
                        n = read(STDIN_FILENO, buffer, BUF_SIZE);
                        //fprintf(stderr, "Here");
                        if (n > 0)
                            break;
                        count++;
                    }
                    
                    if (n == 0) {
                        
                        fprintf(stderr, "Client Exiting!!!\n");
                        close(sockfd);
                        return 0;
                    }
                    
                }
                
                
                if (n > 0) {
                    
                    if(!RAND_bytes(iv, IVSIZE)) {
                        fprintf(stderr, "Error generating random bytes for IV.\n");
                        exit(1);
                    }
                    char *tmp = (char*)malloc(n + IVSIZE);
                    
                    memcpy(tmp, iv, IVSIZE);
                    
                    unsigned char encryption[n];
                    memset(encryption, 0, sizeof(encryption));
                    init_ctr(&state, iv);
                    
                    AES_ctr128_encrypt(buffer, encryption, n, &aes_key, state.ivec, state.ecount, &state.num);
                    memcpy(tmp + IVSIZE, encryption, n);
                    
                    //write(sockfd, tmp, (ssize_t)(n + IVSIZE));
                    
                    while(write(sockfd, tmp, (ssize_t)(n + IVSIZE)) == -1) {
                        fprintf(stderr, "Write failed %zd \n", write(sockfd, tmp, (ssize_t)(n + IVSIZE)));
                    }
                    
                    free(tmp);
                }
                
                
                if (n < BUF_SIZE)
                    break;
            }
            
            while ((n = read(sockfd, buffer, BUF_SIZE)) >= 0) {                  //Read from socket
                int count = 0;
                
                if (n == 0) {
                    n = -1;
                    while (count != 1000) { //count != 10
                        n = read(sockfd, buffer, BUF_SIZE);
                        //fprintf(stderr, "Here");
                        if (n > 0)
                            break;
                        count++;
                    }
                    
                    if (n == 0) {
                        fprintf(stderr, "Client Exiting!!\n");
                        close(sockfd);
                        return 0;
                    }
                }
                
                if (n > 0) {
                    memcpy(iv, buffer, IVSIZE);
                    
                    unsigned char *decryption = (unsigned char*)malloc((n-IVSIZE));
                    //memset(decryption, 0, sizeof(decryption));
                    init_ctr(&state, iv);
                    
                    AES_ctr128_encrypt(buffer + IVSIZE, decryption, (n-IVSIZE), &aes_key, state.ivec, state.ecount, &state.num);
                    
                    while(write(STDOUT_FILENO, decryption, (ssize_t)(n-IVSIZE)) == -1) {
                        fprintf(stderr, "Write failed %zd \n", write(STDOUT_FILENO, decryption, (ssize_t)(n-IVSIZE)));
                    }
 
                    free(decryption);
                }
                
                if (n < BUF_SIZE)
                    break;
            }
        }
        free(buffer);
    }
    //free(buffer);
    return 1;
}
