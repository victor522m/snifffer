# Sniffer Application

## Descripción

La Sniffer Application es una herramienta desarrollada en Java que permite capturar y analizar paquetes de red. Utiliza la biblioteca Pcap4J para capturar paquetes en tiempo real y proporciona una interfaz gráfica desarrollada con JavaFX para facilitar la interacción con el usuario.

## Características

- Captura de paquetes en tiempo real desde diferentes interfaces de red.
- Análisis de paquetes IPv4, IPv6, TCP, UDP e ICMP.
- Visualización de detalles de los paquetes capturados.
- Interfaz gráfica intuitiva con botones para iniciar, pausar y detener la captura de paquetes.

## Requisitos

- Java Development Kit (JDK) 17 o superior.
- JavaFX SDK 20 o superior.
- Pcap4J 1.8.1 o superior.

## Instalación

1. **Descargar el Proyecto**: Clona este repositorio en tu máquina local.

    ```sh
    git clone https://github.com/victor522m/snifffer.git
    cd snifffer
    ```

2. **Configurar las Dependencias**:
    - Añade las bibliotecas de JavaFX al classpath.
    - Asegúrate de tener Pcap4J en tu classpath.

    Si estás utilizando Maven, asegúrate de que tu `pom.xml` incluye las dependencias necesarias:

    ```xml
    <dependencies>
        <dependency>
            <groupId>org.openjfx</groupId>
            <artifactId>javafx-controls</artifactId>
            <version>20</version>
        </dependency>
        <dependency>
            <groupId>org.openjfx</groupId>
            <artifactId>javafx-fxml</artifactId>
            <version>20</version>
        </dependency>
        <dependency>
            <groupId>org.pcap4j</groupId>
            <artifactId>pcap4j-core</artifactId>
            <version>1.8.1</version>
        </dependency>
    </dependencies>
    ```

## Uso

1. **Compilar el Proyecto**:

    ```sh
    mvn clean install
    ```

2. **Ejecutar la Aplicación**:

    ```sh
    mvn javafx:run
    ```

3. **Interacción con la Interfaz Gráfica**:
    - Selecciona una interfaz de red disponible de la lista.
    - Haz clic en "Start Sniffing" para iniciar la captura de paquetes.
    - Utiliza el botón "Pause" para pausar la captura.
    - Utiliza el botón "Exit" para salir de la aplicación.

## Contribuciones

Las contribuciones son bienvenidas. Si tienes alguna sugerencia o encuentras un error, por favor abre una issue o envía un pull request.

## Licencia

Este proyecto está licenciado bajo la Licencia MIT. Ver el archivo [LICENSE](LICENSE) para más detalles.

