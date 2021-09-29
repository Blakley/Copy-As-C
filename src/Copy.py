# ********************************************************************************
#                                    [C]OPY      
#      Author: @Anthlone
#
#       [~  __  ~]         
#       [  /  `  ] _ ._   .
#       [_ \__. _](_)[_)\_|
#                    |  ._|
#             
#      About: Burp Extension to copy GET and POST requests as Curl requests in C
# ********************************************************************************

import re

from burp import IBurpExtender
from burp import IContextMenuFactory

from java.io import PrintWriter
from java.util import ArrayList
from javax.swing import JMenuItem, JMenu
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection


class BurpExtender(IBurpExtender, IContextMenuFactory):
        
    def	registerExtenderCallbacks(self, callbacks):
        self._helpers = callbacks.getHelpers()
        self._callbacks = callbacks
        callbacks.setExtensionName("[C]opy")
        callbacks.registerContextMenuFactory(self)
        self._stdout = PrintWriter(callbacks.getStdout(), True)

    def createMenuItems(self, invocation):
        self._context = invocation
        menu = ArrayList()

        invocation_allowed = [invocation.CONTEXT_MESSAGE_EDITOR_REQUEST, invocation.CONTEXT_PROXY_HISTORY, invocation.CONTEXT_TARGET_SITE_MAP_TABLE]
        
        if self._context.getInvocationContext() in invocation_allowed and len(self._context.selectedMessages) == 1:    
            menu_item = JMenuItem("C Request", actionPerformed = self.create_program)
            menu.add(menu_item)

        request = self._helpers.analyzeRequest(self._context.getSelectedMessages()[0])  
        self.form_data = ''.join(map(chr, self._context.getSelectedMessages()[0].getRequest())).split('\r\n\r\n')[1]
        self.parse_output(request)
        return menu

    def parse_output(self, request): 
        self.request_url =  '"' + request.getUrl().toString() + '";'
        self.request_method = request.getMethod()
        
        # get headers
        self.request_headers = []
        self.headers = request.getHeaders()
        self.headers = dict(item.split(': ',1) for item in self.headers[1:])
        
        self.request_cookies = ''
        self.request_post = ''

        i=0
        for key, value in self.headers.items():
            k = key.encode('ascii', 'ignore')
            v = value.encode('ascii', 'ignore')
            v = v.replace('"', "'")
            hv = k+': '+v

            header_value = ''
            if 'Cookie' in k and self.request_cookies == '':
                hv = hv.replace('Cookie: ', '')
                self.request_cookies = '\t\tcurl_easy_setopt(request, CURLOPT_COOKIE, "' + hv + '");'
                self.request_cookies = '\n\t\t// request cookies\n' + self.request_cookies + '\n'
            else:
                if 'Accept-Encoding' in hv:
                    continue
                header_value = 'headers = curl_slist_append(headers, "' + hv + '");'
                if i==0:
                    self.request_headers.append(header_value)
                else:
                    self.request_headers.append('\t\t' + header_value)
                i+=1

        self.request_headers = self.request_headers = '\n'.join(self.request_headers)

        if len(self.form_data) != 0:
            self.request_post = '\n\t' + 'static const char* post_content = "' + self.form_data + '";' + '\n'

    def create_program(self, event):
            # handle post requests
            post_code = ''
            if self.request_post != '':
                post_code = "\n\t\t// post request\n\t\tcurl_easy_setopt(request, CURLOPT_POSTFIELDS, post_content);\n\t\tcurl_easy_setopt(request, CURLOPT_POSTFIELDSIZE, (long)strlen(post_content));\n"
            
            get_program = '''
/*************************************************************************** 
                            [~  __  ~]         
                            [  /  `  ] _ ._   .
                            [_ \__. _](_)[_)\_|
                                         |  ._|      
***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

#define maxn 1000000

/* Write curl output to variable */
size_t static curl_write(void *buffer, size_t size, size_t nmemb, void *userp) {
     userp += strlen(userp);       
     memcpy(userp, buffer, nmemb);  
     return nmemb;
}

int main(void) {
    CURL *request;
    CURLcode res;
    char* response = (char*)malloc(maxn * sizeof(char)); 
    %s
    curl_global_init(CURL_GLOBAL_DEFAULT);
    request = curl_easy_init();
    
    struct curl_slist *headers = NULL;

    // request url
    char* url = %s
    if (request) {
        curl_easy_setopt(request, CURLOPT_URL, url);

        // request headers
        %s
        curl_easy_setopt(request, CURLOPT_HTTPHEADER, headers);
        %s
            
        curl_easy_setopt(request, CURLOPT_WRITEFUNCTION, curl_write); 
        curl_easy_setopt(request, CURLOPT_WRITEDATA, response);
        %s
        curl_easy_setopt(request, CURLOPT_FOLLOWLOCATION, 1L); // follow redirects
        res = curl_easy_perform(request); // send request   

        curl_easy_cleanup(request);
        curl_slist_free_all(headers);        
    }
    curl_global_cleanup();

    printf("%%s", response); // print output

    return 0;
}
            ''' % (self.request_post, self.request_url, self.request_headers, self.request_cookies, post_code)

            # copy to clipboard
            s = StringSelection(get_program)
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(s, s)

