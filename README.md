# [C]opy Extension for Burp Suite

## Description
  [C]opy is a Burp Suite extension that allows you to copy `GET` and `POST` requests both intercepted and from the proxy history, as a C program.
  The program will be copied to your clipboard.

## Requirements
* [Jython](https://www.jython.org/download.html) >= 2.7.2
* [libcurl](https://curl.se/libcurl/) (to execute the C program)

## Installation
* Download Copy.y
* In Burp Suite, navigate to the `Extender/Extensions` tab, then click the `Add` button and select the `Copy.y` file

## How-To
* Under the `Proxy/HTTP History` tab, right click any request and apply the extension
* When intercepting a request, click the `action` button and then apply the extension


