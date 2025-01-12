#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

using namespace std;

#define SERVER_IP "192.168.1.42" // Altere para o IP do servidor
#define SERVER_PORT 4444

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0};

    // Criando o socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        cerr << "Erro ao criar o socket\n";
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);

    // Convertendo endereço IP para binário
    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        cerr << "Endereço inválido ou não suportado\n";
        return -1;
    }

    // Conectando ao servidor
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        cerr << "Conexão falhou\n";
        return -1;
    }    

    const char *message = "Olá, servidor!";
    send(sock, message, strlen(message), 0);
    cout << "Mensagem enviada ao servidor.\n";

    // Recebendo resposta do servidor
    int valread = read(sock, buffer, 1024);
    cout << "Resposta do servidor: " << buffer << "\n";

    
    // Fechando o socket
    close(sock);

    return 0;
}
