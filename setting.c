#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap.h>
#include "header/setting.h"


int checkAccess(const char *ip, const char *path, const Rule *rules, int ruleCount) {
    for (int i = 0; i < ruleCount; i++) {
        if (strcmp(rules[i].path, path) == 0) {
            if ((rules[i].listType == WHITELIST && strcmp(rules[i].ip, ip) == 0) ||
                (rules[i].listType == BLACKLIST && strcmp(rules[i].ip, ip) != 0)) {
                return 1;  // 액세스 허용
            } else {
                return 0;  // 액세스 거부
            }
        }
    }
    return 1;  // 규칙에 일치하는 항목이 없으면 기본적으로 액세스 허용
}
//config.jason에 규칙설정

void parseConfigFile(const char *configFile, Rule **rules, int *ruleCount)
{
    json_error_t error;
    json_t *root = json_load_file(configFile, 0, &error);
    if (!root) {
        fprintf(stderr, "error: %s\n", error.text);
        exit(1);
    }

    *ruleCount = json_array_size(root);
    *rules = (Rule *)malloc(sizeof(Rule) * (*ruleCount));

    for (int i = 0; i < *ruleCount; i++) {
        json_t *ruleObj = json_array_get(root, i);
        json_t *ipObj = json_object_get(ruleObj, "ip");
        json_t *pathObj = json_object_get(ruleObj, "path");
        json_t *listTypeObj = json_object_get(ruleObj, "list_type");

        if (!json_is_string(ipObj) || !json_is_string(pathObj) || !json_is_string(listTypeObj)) {
            fprintf(stderr, "error.\n"); //규칙이 잘못될때
            exit(1);
        }

        Rule *rule = &(*rules)[i];
        strncpy(rule->ip, json_string_value(ipObj), MAX_IP_LENGTH);
        strncpy(rule->path, json_string_value(pathObj), MAX_PATH_LENGTH);

        const char *listType = json_string_value(listTypeObj);
        if (strcmp(listType, "whitelist") == 0) {
            rule->listType = WHITELIST; //화이트 리스트 규칙
        } else if (strcmp(listType, "blacklist") == 0) {
            rule->listType = BLACKLIST; //블랙리스트 규칙
        } else {
            fprintf(stderr, "설정 파일에 잘못된 목록 유형이 포함되어 있습니다.\n");
            exit(1);
        }
    }

    json_decref(root);     
}
//config파일로 수정
int getInaccessibleFiles(const char *ip, const char *configFile, const char ***inaccessibleFiles) {
    Rule *rules;
    int ruleCount;
    parseConfigFile(configFile, &rules, &ruleCount);

    int fileCount = ruleCount;
    *inaccessibleFiles = (const char **)malloc(sizeof(const char *) * fileCount);
    int inaccessibleCount = 0;

    for (int i = 0; i < fileCount; i++) {
        const char *file = rules[i].path;
        int accessGranted = 0;

        if ((rules[i].listType == WHITELIST && strcmp(rules[i].ip, ip) == 0) ||
            (rules[i].listType == BLACKLIST && strcmp(rules[i].ip, ip) != 0)) {
            accessGranted = 1;
        }

        if (!accessGranted) {
            (*inaccessibleFiles)[inaccessibleCount] = file;
            inaccessibleCount++;
        }
    }

    free(rules);

    return inaccessibleCount;
}

// 메모리문제 해결
// rules를 내부에서 정의하지 않고 직접 받아옴
int getInaccessibleFilesV2(const char *ip, const Rule* rules, int ruleCount, const char ***inaccessibleFiles) {
    // Rule *rules;
    // int ruleCount;
    // parseConfigFile(configFile, &rules, &ruleCount);

    int fileCount = ruleCount;
    *inaccessibleFiles = (const char **)malloc(sizeof(const char *) * fileCount);
    int inaccessibleCount = 0;

    for (int i = 0; i < fileCount; i++) {
        const char *file = rules[i].path;
        int accessGranted = 0;

        if ((rules[i].listType == WHITELIST && strcmp(rules[i].ip, ip) == 0) ||
            (rules[i].listType == BLACKLIST && strcmp(rules[i].ip, ip) != 0)) {
            accessGranted = 1;
        }

        if (!accessGranted) {
            (*inaccessibleFiles)[inaccessibleCount] = file;
            inaccessibleCount++;
        }
    }

    //free(rules);

    return inaccessibleCount;
}

// void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
//     //패킷에서 아이피 주소와 파일경로 추출
//     const struct ip *ipHeader = (struct ip *)(packet + 14);
//     const char *srcIp = inet_ntoa(ipHeader->ip_src);
//     const char *dstIp = inet_ntoa(ipHeader->ip_dst);

//     char filePath[MAX_PATH_LENGTH]; //파일경로
    

//     // 파일목록
//     const char *files[] = {
//         /*
//         "/path/to/file1.txt",
//         "/path/to/file2.txt",
//         "/path/to/file3.txt"
//         */
//     };
//     int fileCount = sizeof(files) / sizeof(files[0]); 

//     //접근 가능파일
//     const Rule *rules = (const Rule *)userData;
//     int ruleCount = *(int *)pkthdr;
//     const char **inaccessibleFiles;
//     int inaccessibleCount = getInaccessibleFiles(srcIp, rules, ruleCount, files, fileCount, &inaccessibleFiles);
//     //함수호출 getInaccessibleFiles 접근가능 파일목록 반환
//     // 접근가능 파일목록 추출
//     printf("Inaccessible files for IP %s:\n", srcIp);
//     for (int i = 0; i < inaccessibleCount; i++) {
//         printf("- %s\n", inaccessibleFiles[i]);
//     }

//     // 접근 불가능한 파일 목록 메모리 해제
//     free(inaccessibleFiles);
// }
