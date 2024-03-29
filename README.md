# [C]opy Extension for Burp Suite

## Description
  [C]opy is a Burp Suite extension that allows you to copy `GET` and `POST` requests both intercepted and from the proxy history, as a C program.
  The program will be copied to your clipboard.

## Requirements
* [Jython](https://www.jython.org/download.html) >= 2.7.2
* [libcurl](https://curl.se/libcurl/) (to execute the C program)
  * bash: `sudo apt-get update
sudo apt-get install libcurl4-openssl-dev
`

## Installation
* Download Copy.y
* In Burp Suite, navigate to the `Extender/Extensions` tab, then click the `Add` button and select the `Copy.y` file

## How-To
* Under the `Proxy/HTTP History` tab, right click any request and apply the extension
* When intercepting a request, click the `action` button and then apply the extension
* To run the C program, run the following command `gcc program.c -lcurl` then execute the generated `a.out` file

### Extension Screenshot
![Alt text](burp.png?raw=true)

### Output Screenshot
![Alt text](program.png?raw=true)

### Todo
* Dynamically manage response buffer
* Add helpful code snippets
