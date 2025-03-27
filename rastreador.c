#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>

#define MAX_LLAMADAS 512
#define NOMBRE_ARCHIVO "syscalls.csv"

int contador_llamadas[MAX_LLAMADAS] = {0};
int opcion_v = 0;
int opcion_V = 0;
char *syscalls[MAX_LLAMADAS] = {NULL};
char *descripciones[MAX_LLAMADAS] = {NULL};

void cargar_syscalls() {
    FILE *archivo = fopen(NOMBRE_ARCHIVO, "r");
    if (!archivo) {
        perror("Error al abrir el archivo de syscalls");
        exit(EXIT_FAILURE);
    }

    int numero;
    char nombre[256];
    char descripcion[512];
    while (fscanf(archivo, "%d,%255[^,],%511[^\n]", &numero, nombre, descripcion) == 3) {
        if (numero >= 0 && numero < MAX_LLAMADAS) {
            syscalls[numero] = strdup(nombre);
            descripciones[numero] = strdup(descripcion);
        }
    }

    fclose(archivo);
}

void imprimir_tabla_llamadas() {
    printf("\n| Syscall Name      | Count |\n");
    printf("|-------------------|-------|\n");
    for (int i = 0; i < MAX_LLAMADAS; i++) {
        if (contador_llamadas[i] > 0) {
            printf("| %-17s | %-5d |\n",
                   (syscalls[i] != NULL) ? syscalls[i] : "desconocido",
                   contador_llamadas[i]);
        }
    }
}

void imprimir_funciones_utilizadas() {
    printf("\n----- Funciones Utilizadas y su descripción -----\n");
    for (int i = 0; i < MAX_LLAMADAS; i++) {
        if (contador_llamadas[i] > 0) {
            printf(" - %s: %s\n",
                   (syscalls[i] != NULL) ? syscalls[i] : "desconocida",
                   (descripciones[i] != NULL) ? descripciones[i] : "Sin descripción");
        }
    }
}

void rastrear_proceso(pid_t pid) {
    int estado;
    struct user_regs_struct registros;

    waitpid(pid, &estado, 0);
    while (1) {
        if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) break;
        waitpid(pid, &estado, 0);
        if (WIFEXITED(estado)) break;

        ptrace(PTRACE_GETREGS, pid, NULL, &registros);
        long numero_llamada = registros.orig_rax;

        if (numero_llamada >= 0 && numero_llamada < MAX_LLAMADAS) {
            contador_llamadas[numero_llamada]++;
            if (opcion_v || opcion_V) {
                printf("[+] System Call: %ld -> %s\n", numero_llamada,
                       (syscalls[numero_llamada] != NULL) ? syscalls[numero_llamada] : "desconocida");
                if (opcion_V) {
                    printf("Presione Enter para continuar...");
                    getchar();
                }
            }
        }

        if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) break;
        waitpid(pid, &estado, 0);
        if (WIFEXITED(estado)) break;
    }
    imprimir_tabla_llamadas();
    imprimir_funciones_utilizadas();
}

int main(int argc, char *argv[]) {
    cargar_syscalls();

    int indice_proceso = 1;
    while (indice_proceso < argc && argv[indice_proceso][0] == '-') {
        if (strcmp(argv[indice_proceso], "-v") == 0) {
            opcion_v = 1;
        } else if (strcmp(argv[indice_proceso], "-V") == 0) {
            opcion_V = 1;
        } else {
            break;
        }
        indice_proceso++;
    }

    if (indice_proceso >= argc) {
        fprintf(stderr, "Error: No se especificó el programa a rastrear.\n");
        exit(EXIT_FAILURE);
    }

    pid_t pid = fork();
    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execvp(argv[indice_proceso], &argv[indice_proceso]);
        perror("Error al ejecutar el programa");
        exit(EXIT_FAILURE);
    } else if (pid > 0) {
        rastrear_proceso(pid);
    } else {
        perror("Error al crear el proceso");
        exit(EXIT_FAILURE);
    }

    return 0;
}
