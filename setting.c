#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap.h>
#include "header/setting.h"

int checkAccess(const char *ip, const char *path, const Rule *rules, int ruleCount) {
    for (int i = 0; i < ruleCount; i++) {
        if (strcmp(rules[i].path, path) == 0) {
            if (rules[i].listType == WHITELIST) {
                int ipMatch = 0;
                for (int j = 0; j < ruleCount; j++) {
                    if (strcmp(rules[j].ip, ip) == 0) {
                        ipMatch = 1;
                        break;
                    }
                }
                if (ipMatch) {
                    return 1;  //접근허용
                }
            } else if (rules[i].listType == BLACKLIST) {
                int ipMatch = 0;
                for (int j = 0; j < ruleCount; j++) {
                    if (strcmp(rules[j].ip, ip) == 0) {
                        ipMatch = 1;
                        break;
                    }
                }
                if (!ipMatch) {
                    return 1;  // 접근허용
                }
            }
            return 0;  // 접근 거부
        }
    }
    return 1;  // 규칙에 일치하는 항목이 없으면 기본적으로 액세스 허용
}


//config.jason에 규칙설정
*/
double isAlwaysCheck(const char *ip, const char *path, const Rule *rules, int ruleCount) {
    for (int i = 0; i < ruleCount; i++) {
        if (strcmp(rules[i].path, path) == 0) {
            // 대상 파일 규칙 찾으면 sameRate 리턴
            return rules[i].sameRate;
        }
    }
    return -1;  // 규칙에 일치하는 항목이 없으면 음수 리턴
}

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
        /*
        추가한 구조체 읽어오는 함수
        */
        json_t *alwaysCheckObj = json_object_get(ruleObj, "always_check");
        json_t *sameRateObj = json_object_get(ruleObj, "same_rate");

        if (!json_is_string(ipObj) || !json_is_string(pathObj) || !json_is_string(listTypeObj)|| !json_is_integer(alwaysCheckObj)|| !json_is_number(sameRateObj)) {
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
        /*
        json_number_value()로 json파일에서 값을 읽어와서 구조체에 저장
        ->double형태를 반환함->alwaysCheck는 int형태이므로 형변환(int)
        */
        rule->alwaysCheck = json_integer_value(alwaysCheckObj); 
        rule->sameRate = json_number_value(sameRateObj);
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

        if (rules[i].listType == WHITELIST) {
            if (strcmp(rules[i].ip, ip) == 0) {
                accessGranted = 1;
            }
        } else if (rules[i].listType == BLACKLIST) {
            int ipMatch = 0;
            for (int j = 0; j < ruleCount; j++) {
                if (strcmp(rules[j].ip, ip) == 0) {
                    ipMatch = 1;
                    break;
                }
            }
            if (!ipMatch) {
                accessGranted = 1;
            }
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
