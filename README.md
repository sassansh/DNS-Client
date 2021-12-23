<!-- PROJECT LOGO -->
<br />
<p align="center">
 <a href="https://github.com/sassansh/DNS-Client">
    <img src="/images/logo.png" alt="Logo" width="80" height="80">
  </a>
  <h2 align="center">A DNS Client</h2>

  <p align="center">
     Command-line interface for DNS resolver system. Built as a group programming assignment for UBC <a href="https://courses.students.ubc.ca/cs/courseschedule?pname=subjarea&tname=subj-course&dept=CPSC&course=317">CPSC 317</a> (Internet Computing).
  </p>
</p>

<!-- ![Assignment Question](/images/interface.png) -->

## Table of Contents

- [Goals 🎯](#goals-)
- [Technology Stack 🛠️](#technology-stack-)
- [Prerequisites 🍪](#prerequisites-)
- [Setup 🔧](#setup-)
- [Assignment Description 📚](#assignment-description-)
- [Team ‎😃](#team-)

## Goals 🎯

The goals of this assignment are:

- To learn how to use UDP datagram sockets in Java.
- o study and understand the implementation of the DNS protocol.
- To learn how to read and implement a well specified protocol.
- To improve your programming and debugging skills as they relate to the use of datagrams in Java.
- To develop general networking debugging skills.
- To develop an understanding of how to send and receive binary data.

## Technology Stack 🛠️

[Java](https://www.java.com/en/)

## Prerequisites 🍪

You should have [JDK 10](https://www.oracle.com/ca-en/java/technologies/java-archive-javase10-downloads.html), [IntelliJ IDEA](https://www.jetbrains.com/idea/) and [Git](https://git-scm.com/) installed on your PC.

## Setup 🔧

1. Clone the repo using:

   ```bash
     git clone https://github.com/sassansh/DNS-Client.git
   ```

2. Open the project in IntelliJ.

3. To open the GUI, Run: `ca.ubc.cs317.dnslookup.DNSLookupCUI`

## Assignment Description 📚

### Special Note

This assignment is being released without an autograder, as the test process is still under development. This should enable you to start working on it until the autograder is released.

### Assignment Overview

In this assignment you will use the Java DatagramSocket class and related libraries to create a DNS resolver system. As in the previous assignment you will complete specific sections of an existing application that already provides the UI functionality (via a command-line interface). You are responsible for implementing the data transfer associated to the protocol.

To start your assignment, download the file [DNSLookupService.zip](https://ca.prairielearn.com/pl/course_instance/2347/instance_question/10685205/clientFilesQuestion/DNSLookupService.zip). This file contains a directory called `DNSLookupService` which can be imported into IDEs like IntelliJ or Eclipse to develop your code.

The file above contains a skeleton code that provides a console-based user-interface for the functionality you are to implement. The interface, however, does not actually transfer any data. Your job is to implement the data transfer and response parsing for this application. More specifically, you will need to implement the code that performs each of the following tasks:

- Build a DNS iterative query based on a host name (FQDN), type and class.
- Send this query to a specified nameserver and receive its response.
- Parse the response from the nameserver, extracting all relevant information and resource records.
- If the response does not contain the expected answer but directs your client to a different nameserver, proceed with querying the provided nameservers.

Remember, you are only required to implement a subset of the protocol, so some of the material in the references goes beyond what you need. Keep in mind that the RFC describes the data (protocol) exchanges between the DNS client (i.e., what you are writing) and a DNS nameserver.

All the functionality listed above is based on the implementation of the constructor and methods of the class `ca.ubc.cs.cs317.dnslookup.DNSLookupService`, available in the provided code. This is the only file you are allowed to change.

You are not permitted to use any built-in or Java library methods to convert domain names to IP addresses. While the provided code uses the `getByName()` method of `InetAddress` to convert a string to its corresponding IP address, it should not be used in any other context except to convert a dotted-decimal IP address (e.g., 199.7.83.42) to its corresponding `InetAddress` object. You can also use `InetAddress.getByAddress()` to convert an IP address to its string representation (dotted-decimal or IPv6-based). Note that the testing environment will limit your ability to contact DNS servers other than the ones provided by the autograder, so using such a resolution system will often result in errors in autograding.

## Team ‎😃

Sassan Shokoohi - [GitHub](https://github.com/sassansh) - [LinkedIn](https://www.linkedin.com/in/sassanshokoohi/) - [Personal Website](https://sassanshokoohi.ca)

Lana Kashino - [GitHub](https://github.com/lanakashino) - [LinkedIn](https://www.linkedin.com/in/lanakashino/) - [Personal Website](https://lanakashino.com)

Project Link: [https://github.com/sassansh/DNS-Client](https://github.com/sassansh/DNS-Client)

[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://www.linkedin.com/in/sassanshokoohi/
