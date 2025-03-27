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


#define MAX_LLAMADAS 512 // Número máximo de syscalls a rastrear
#define NOMBRE_ARCHIVO "syscalls.csv" // Archivo que contiene las syscalls y sus descripciones

// Opciones
int opcion_v = 0;   
int opcion_V = 0;   

int contador_syscalls[MAX_LLAMADAS] = {0}; // Array para contar la cantidad de cada syscall
char *syscalls[MAX_LLAMADAS] = {NULL};       
char *descripciones[MAX_LLAMADAS] = {NULL};  

// Función que carga los nombres y descripciones de syscalls desde el archivo CSV
void cargar_syscalls() {

    FILE *archivo = fopen(NOMBRE_ARCHIVO, "r");

    if (!archivo) {
        perror("Error al abrir el archivo de syscalls");
        exit(EXIT_FAILURE);
    }

    int numero;
    char nombre[256];
    char descripcion[512];

    // Leer el archivo y almacenar el número, nombre y descripción de cada syscall
    while (fscanf(archivo, "%d,%255[^,],%511[^\n]", &numero, nombre, descripcion) == 3) {
        if (numero >= 0 && numero < MAX_LLAMADAS) {
            syscalls[numero] = strdup(nombre);       
            descripciones[numero] = strdup(descripcion); 
        }
    }
    fclose(archivo); 
}

// Función para imprimir la tabla de syscalls con su cantidad respectiva
void imprimir_syscall() {
    printf("\n| Syscall           | Cantidad |\n");
    printf("|-------------------|----------|\n");
   
    for (int i = 0; i < MAX_LLAMADAS; i++) {
        // Imprimir solo las syscalls que se utilizaron 
        if (contador_syscalls[i] > 0) {
            printf("| %-17s | %-8d |\n",
                   (syscalls[i] != NULL) ? syscalls[i] : "desconocida",
                   contador_syscalls[i]);
        }
    }
}

// Función para imprimir las descripciones de las syscalls utilizadas
void imprimir_descripcion() {
    printf("\n----- Descripción de syscalls -----\n");
    for (int i = 0; i < MAX_LLAMADAS; i++) {

        // Imprimir solo las syscalls que se utilizaron 
        if (contador_syscalls[i] > 0) {
            printf(" - %s: %s\n",
                   (syscalls[i] != NULL) ? syscalls[i] : "desconocida",
                   (descripciones[i] != NULL) ? descripciones[i] : "Sin descripción");
        }
    }
}

// Función principal de rastreo de procesos 
void rastrear_proceso(pid_t pid) {

    int estado; // Almacena el estado del proceso que se esta rastreando
    struct user_regs_struct registros; // Estructura para almacenar los registros del proceso

    waitpid(pid, &estado, 0); // Espera inicial para  el hijo

    while (1) {
        if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) break; // Rastrear la siguiente syscall 

        waitpid(pid, &estado, 0); // Espera a que el hijo complete la syscall
        
        if (WIFEXITED(estado)) break; // Sale si el proceso ya terminó

        ptrace(PTRACE_GETREGS, pid, NULL, &registros); // Obtener los registros del proceso rastreado
        long numero_llamada = registros.orig_rax; // Obtiene el número de la syscall

        if (numero_llamada >= 0 && numero_llamada < MAX_LLAMADAS) {
            contador_syscalls[numero_llamada]++;

            if (opcion_v || opcion_V) {
                printf("[+] System Call: %ld -> %s\n", numero_llamada,
                       (syscalls[numero_llamada] != NULL) ? syscalls[numero_llamada] : "desconocida");
                
                // Si está en modo -V, esperar al usuario para continuar
                if (opcion_V) {
                    printf("Presione Enter para continuar...");
                    getchar();
                }
            }
        }

        // Se continua rastreando la siguiente syscall
        if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) break;
        waitpid(pid, &estado, 0); 
        if (WIFEXITED(estado)) break; 
    }
    imprimir_syscall();      
    imprimir_descripcion();  
}

// Función main del programa
int main(int argc, char *argv[]) {
    cargar_syscalls(); 

    int i = 1;

    // Verifica los modos de uso
    while (i < argc && argv[i][0] == '-') {
        if (strcmp(argv[i], "-v") == 0) {
            opcion_v = 1; 
        } 
        else if (strcmp(argv[i], "-V") == 0) {
            opcion_V = 1; 
        } else {
            break; 
        }
        i++;
    }

    // Verificar si se ingreso un programa a rastrear
    if (i >= argc) {
        fprintf(stderr, "Error: No se ingreso el programa a rastrear.\n");
        exit(EXIT_FAILURE);
    }

    pid_t pid = fork(); // Crear un proceso hijo para rastrear el programa 

    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL); // Se va a rastrear el proceso hijo
        execvp(argv[i], &argv[i]); // Ejecutar el programa 
        perror("Error al ejecutar el programa");
        exit(EXIT_FAILURE);
    } else if (pid > 0) {
        rastrear_proceso(pid); // Padre rastrea el hijo
    } else {
        perror("Error al crear el proceso"); 
        exit(EXIT_FAILURE);
    }

    return 0;
}
