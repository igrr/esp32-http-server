# Simple HTTP server

This is a very minimal HTTP server I use in some of the projects.

Absolutely not ready for any kind of production use.


# How to use

Really, please see above note.

This directory is an ESP-IDF component. Clone it (or add it as a submodule) into the component directory of the project.


# Documentation

None yet, but I tried to make the comments in the header file helpful.


# Examples

Examples functions at http server

## GET Method Example
 
`simple_GET_method_example()` function:

* Add http_server.c and http_server.h as a component into your project.
* Server initialization added into the example function, simply call it and it should work!
* Receiving a GET request at /, http server response is a "Hello World, from ESP32!" html.

## POST Method Example
`simple_POST_method_example()` function:
* As well as GET example, simply add http_server as a componente into your ESP-IDF project.
* Server initialization added into the POST example function, simply call it and don't worry.
* Post to / a pair of key-value where the key is 'key' and value some value you want to test. The example will show value content. If needed, increade log verbosity at `make menuconfig` to show all parsed key-value pairs.

# Debugging

Increasing log level to "Verbose" should produce lots of output related to request handling.


# License

GPL, see [LICENSE](LICENSE) file. Mostly because this is a very early version. Will be relicensed as something more reasonable later.

