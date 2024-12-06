# Implementation Spring Security 6 with JWT in Spring Boot 3

## Introduction

This README outlines the steps to configure a secure authentication and authorization system using Spring Security 6, OAuth2 and JWT.

## Prerequisites

- JDK 17+
- Spring Boot 3.x
- Maven/Gradle for dependency management

### Dependencies

Include the following in your `pom.xml` or `build.gradle`:
- **Spring Boot Starter Web**: REST API support.
- **Spring Boot Starter Security**: Security framework.
- **Spring Boot Starter OAuth2 Resource Server**: JWT resource server support.
- **Lombok**: Provides annotations.

### Create public and private keys for encryption and decryption

Now in the resources directory create a folder called certs and then open the terminal and navigate into that directory.

 `cd src/main/resources/certs`

Then generate a Private Key ([RSA](https://www.geeksforgeeks.org/rsa-algorithm-cryptography/)):

    openssl genpkey -algorithm RSA -out private-key1.pem

This command generates an RSA private key and saves it to the private-key1.pem file.

Extract the Public Key from the Private Key by running:

    openssl rsa -pubout -in private-key1.pem -out public-key.pem

Then convert it to the appropriate [PCKS](https://ar5iv.labs.arxiv.org/html/1207.5446) format and replace the old one

    openssl pkcs8 -topk8 -inform PEM -outform PEM -in private-key1.pem -out private-key.pem -nocrypt

Finally delete `private-key1.pem`.

## Contributing to This Repository

This project is a personal initiative, but I believe in the power of collaboration to create something truly impactful. Whether you're exploring Spring Security, OAuth, or JWT for the first time or have advanced expertise, your perspective can make a big difference.

Here’s how you can contribute:

- Report Issues: If you encounter any bugs or have suggestions for improvements, please open an issue in the repository.

- Submit Pull Requests: Found a solution or enhancement? Fork the repository, implement your changes, and submit a pull request.

- Share Knowledge: Have an idea for better documentation, a new example, or advanced configurations? Feel free to contribute!

Together, we can make this project a helpful resource for developers worldwide. Let’s collaborate and grow! 🚀

