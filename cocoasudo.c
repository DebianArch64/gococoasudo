//
//  cocoasudo.m
//
//  Created by Aaron Kardell on 10/19/2009.
//  Copyright 2009 Performant Design, LLC. All rights reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/stat.h>
#include <unistd.h>
#include <Security/Authorization.h>
#include <Security/AuthorizationTags.h>

char *addFileToPath(const char *path, const char *filename) {
    char *outbuf;
    char *lc;

    lc = (char *)path + strlen(path) - 1;
    
    if (lc < path || *lc != '/') {
        lc = NULL;
    }
    
    while (*filename == '/') {
        filename++;
    }
    
    outbuf = malloc(strlen(path) + strlen(filename) + 1 + (lc == NULL ? 1 : 0));
    
    sprintf(outbuf, "%s%s%s", path, (lc == NULL) ? "/" : "", filename);
    
    return outbuf;
}

int isExecFile(const char *name) {
    struct stat s;
    
    return (!access(name, X_OK) && !stat(name, &s) && S_ISREG(s.st_mode));
}

char *which(const char *filename)
{
    char *path, *p, *n;
    
    path = getenv("PATH");
    
    if (!path) {
        return NULL;
    }

    p = path = strdup(path);
    
    while (p) {
        n = strchr(p, ':');
        
        if (n) {
            *n++ = '\0';
        }
        
        if (*p != '\0') {
            p = addFileToPath(p, filename);
            
            if (isExecFile(p)) {
                free(path);
                
                return p;
            }
            
            free(p);
        }
        
        p = n;
    }
    
    free(path);
    
    return NULL;
}

AuthorizationRef authRef = NULL;
int cocoaSudo(char *executable, char *commandArgs[], char *icon, char *prompt) {
    OSStatus status = errAuthorizationSuccess;
    AuthorizationFlags flags = kAuthorizationFlagDefaults;
    int retVal = 1;
    if (authRef == NULL)
    {
        AuthorizationItem right = {kAuthorizationRightExecute, 0, NULL, 0};
        AuthorizationRights rightSet = {1, &right};
        
        AuthorizationEnvironment myAuthorizationEnvironment;
        AuthorizationItem kAuthEnv[2];
        myAuthorizationEnvironment.items = kAuthEnv;
        
        if (prompt && icon) {
            kAuthEnv[0].name = kAuthorizationEnvironmentPrompt;
            kAuthEnv[0].valueLength = strlen(prompt);
            kAuthEnv[0].value = prompt;
            kAuthEnv[0].flags = 0;
            
            kAuthEnv[1].name = kAuthorizationEnvironmentIcon;
            kAuthEnv[1].valueLength = strlen(icon);
            kAuthEnv[1].value = icon;
            kAuthEnv[1].flags = 0;
            
            myAuthorizationEnvironment.count = 2;
        }
        else if (prompt) {
            kAuthEnv[0].name = kAuthorizationEnvironmentPrompt;
            kAuthEnv[0].valueLength = strlen(prompt);
            kAuthEnv[0].value = prompt;
            kAuthEnv[0].flags = 0;
            
            myAuthorizationEnvironment.count = 1;
        }
        else if (icon) {
            kAuthEnv[0].name = kAuthorizationEnvironmentIcon;
            kAuthEnv[0].valueLength = strlen(icon);
            kAuthEnv[0].value = icon;
            kAuthEnv[0].flags = 0;
            
            myAuthorizationEnvironment.count = 1;
        }
        else {
            myAuthorizationEnvironment.count = 0;
        }
        
        status = AuthorizationCreate(NULL, &myAuthorizationEnvironment, flags, &authRef);
        
        if (status != errAuthorizationSuccess) {
            printf("Could not create authorization reference object.\n");
            status = errAuthorizationBadAddress;
        }
        else {
            flags = kAuthorizationFlagDefaults |
            kAuthorizationFlagInteractionAllowed |
            kAuthorizationFlagPreAuthorize |
            kAuthorizationFlagExtendRights;
            
            status = AuthorizationCopyRights(authRef, &rightSet, &myAuthorizationEnvironment, flags, NULL);
        }
    }
    if (status == errAuthorizationSuccess) {
        FILE *ioPipe;
        char buffer[1024];
        int bytesRead;

        flags = kAuthorizationFlagDefaults;
        status = AuthorizationExecuteWithPrivileges(authRef, executable, flags, commandArgs, &ioPipe);
        /* Just pipe processes' stdout to our stdout for now; hopefully can add stdin pipe later as well */
        printf("Authorization Result Code: %d\n", status);
        if (status == errAuthorizationSuccess) {
            for (;;) {
                bytesRead = fread(buffer, sizeof(char), 1024, ioPipe);
                
                if (bytesRead < 1) {
                    break;
                }
                
                write(STDOUT_FILENO, buffer, bytesRead * sizeof(char));
            }
        }
        
        pid_t pid;
        int pidStatus;
        
        do {
            pid = wait(&pidStatus);
        } while (pid != -1);
        
        if (status == errAuthorizationSuccess) {
            retVal = 0;
        }
    }
    else {
        AuthorizationFree(authRef, kAuthorizationFlagDestroyRights);
        authRef = NULL;
        
            if (status != errAuthorizationCanceled) {
            // pre-auth failed
            printf("Pre-auth failed\n");
        }
    }
    
    return retVal;
}

#include <assert.h>
int split(char* str, const char delimeter, char*** args) {
    int cnt = 1;
    char* t = str;

    while (*t == delimeter) t++;

    char* t2 = t;
    while (*(t2++))
        if (*t2 == delimeter && *(t2 + 1) != delimeter && *(t2 + 1) != 0) cnt++;

    (*args) = malloc(sizeof(char*) * (cnt + 1));

    for(int i = 0; i < cnt; i++) {
        char* ts = t;
        while (*t != delimeter && *t != 0) t++;

        int len = (t - ts + 1);
        (*args)[i] = malloc(sizeof(char) * len);
        memcpy((*args)[i], ts, sizeof(char) * (len - 1));
        (*args)[i][len - 1] = 0;

        while (*t == delimeter) t++;
    }

    return cnt;
}

int simple_cocoa(char *executable, char *command, char *message)
{
    int status = -1;
    if (executable) {
        char **tokens;
        int count = split(command, ' ',&tokens);
        if (tokens)
        {
            tokens[count] = NULL;
            status = cocoaSudo(executable, tokens, NULL,message);
            for (int i = 0; i < count; i++) free (tokens[i]);
            free (tokens);
        }
    }
    return status;
}
