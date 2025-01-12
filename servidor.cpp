#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

using namespace std;

#define PORT 4444

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[1024] = {0};

    // Criando o socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Falha ao criar o socket");
        exit(EXIT_FAILURE);
    }

    // Configurando opções do socket
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("Falha em setsockopt");
        exit(EXIT_FAILURE);
    }

    // Configurando endereço do servidor
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Associando o socket à porta
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Falha ao associar o socket");
        exit(EXIT_FAILURE);
    }

    // Escutando conexões
    if (listen(server_fd, 3) < 0) {
        perror("Falha em listen");
        exit(EXIT_FAILURE);
    }

    cout << "Aguardando conexão na porta " << PORT << "...\n";

    // Aceitando uma conexão
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
        perror("Falha ao aceitar conexão");
        exit(EXIT_FAILURE);
    }

    // Recebendo dados do cliente
    int valread = read(new_socket, buffer, 1024);
    cout << "Mensagem recebida: " << buffer << "\n";

    // Respondendo ao cliente
    const char *response = "Mensagem recebida pelo servidor!";
    send(new_socket, response, strlen(response), 0);
    cout << "Resposta enviada ao cliente.\n";

    // Fechando o socket
    close(new_socket);
    close(server_fd);

    return 0;
}
