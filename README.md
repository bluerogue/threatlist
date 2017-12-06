# Threatlist Aggregator and API 

This application pulls in a number of OSINT malicious IP feeds and aggregates them. Lists are automatically updated daily and previous lists are archived for reference. The compiled lists are aggressive and may include tens of thousands of entries. A built-in API allows direct access to lists and other functions. 

### Prerequisites

* Java 8
* Maven 3
* Tomcat or other servlet container to run the WAR (if not running directly)

### Running

To run as a simple Java application:

```
mvn spring-boot:run
```

To generate a WAR file:

```
mvn clean install
```

## Built With

* [Spring Boot](https://projects.spring.io/spring-boot/) -- Application Framework
* [Maven](https://maven.apache.org/) -- Dependency Management

## Authors

* **Matthew Roberts** -- [matthewroberts.io](https://www.matthewroberts.io)

## License

This project is licensed under the MIT License -- see the [LICENSE.txt](LICENSE.txt) file for details