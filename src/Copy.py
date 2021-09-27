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

from burp import IBurpExtender
from burp import IProxyListener
from burp import IContextMenuFactory

from java.io import PrintWriter
from java.util import ArrayList
from javax.swing import JMenuItem, JMenu
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection

class BurpExtender(IBurpExtender, IContextMenuFactory, IProxyListener):
        
    def	registerExtenderCallbacks(self, callbacks):
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # set our extension name
        callbacks.setExtensionName("[C]opy")
        
        # setup menu
        callbacks.registerContextMenuFactory(self)

         # obtain our output stream
        self._stdout = PrintWriter(callbacks.getStdout(), True)

        # register listeners
        callbacks.registerProxyListener(self)


    def createMenuItems(self, invocation):
        # TODO: add code for POST in C
        # TODO: clean up code, add github documentation
        
        self._context = invocation
        menu = ArrayList()

        invocation_allowed = [invocation.CONTEXT_MESSAGE_EDITOR_REQUEST, invocation.CONTEXT_PROXY_HISTORY, invocation.CONTEXT_TARGET_SITE_MAP_TABLE]
        
        if self._context.getInvocationContext() in invocation_allowed and len(self._context.selectedMessages) == 1:    
            menu_item = JMenuItem("C Request", actionPerformed = self.createProgram)
            menu.add(menu_item)

        request = self._helpers.analyzeRequest(self._context.getSelectedMessages()[0])  
        
        # extract content out of response
        value = str(request.getHeaders())
        value = value[1:]
        value = value[:-1]

        content = value.split(',')
        content = [x.strip(' ') for x in content]
        content = list(filter(None, content))

        methods = ['GET', 'POST']
        self.request_method = ""
        self.request_url = ""
        request_host = ""
        self.request_cookies = ""
        self.request_headers =  []

        first = 0
        for item in content:
            if item.startswith(tuple(methods)):
                self.request_method = item.split(' ')[0]
                self.request_url = item.split(' ')[1]

            elif item.startswith('Host'):
                request_host = item.split(' ')[1]
                request_host = 'curl_slist_append(headers, "Host: ' + request_host + '");'

            elif item.startswith('Cookie'):
                data = item.split(' ')
                data.pop(0)
                self.request_cookies = ' '.join(data)
                self.request_cookies = 'curl_easy_setopt(request, CURLOPT_COOKIE, "' + self.request_cookies + '");'

            else:
                header_value = item.replace('"', "'")
                if first == 1:
                    header_value = '\t\tcurl_slist_append(headers, "' + header_value + '");'
                else:
                    header_value = 'curl_slist_append(headers, "' + header_value + '");'
                self.request_headers.append(header_value)    
                first = 1
                
        host = (request_host[request_host.find('"')+len('"'):request_host.rfind('"')]).split(' ')[1]
        self.request_url =  '"'+host + self.request_url+'";' + '\n'
        self.request_headers.append('\t\t' + request_host)
        self.request_headers = self.request_headers = '\n'.join(self.request_headers)
        
        self.request_cookies = '// request cookies\n' + '\t\t' + self.request_cookies
        if self.request_cookies.strip() == '// request cookies':
            self.request_cookies = ''
        
        return menu


    def createProgram(self, event):
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

#define maxn 1000000 // max response length

/* Write curl output to variable */
size_t static curl_write(void *buffer, size_t size, size_t nmemb, void *userp) {
    userp += strlen(userp);       
    memcpy(userp, buffer, nmemb);  
    return nmemb;
}

int main(void) {
    CURL *request;
    CURLcode res;
    char* response = (char*)malloc(maxn * sizeof(char)); // response content

    curl_global_init(CURL_GLOBAL_DEFAULT);
    request = curl_easy_init();

    // request url
    char* url = %s
    if (request) {
        struct curl_slist *headers = NULL;
        
        // request headers
        %s
        
        %s

        // send request
        curl_easy_setopt(request, CURLOPT_WRITEDATA, response); // output variable
        res = curl_easy_perform(request);

        curl_slist_free_all(headers);        
        curl_easy_cleanup(request);
    }

    curl_global_cleanup();

    // Do stuff with output
    char* ret;
    ret = strstr(response, "google");
    if (ret)
        printf(response); // print output
    else
        printf("google was found in response");

    return 0;
}
        ''' % (self.request_url, self.request_headers, self.request_cookies)

        # copy to clipboard
        if self.request_method == 'GET':
            s = StringSelection(get_program)
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(s, s)

        