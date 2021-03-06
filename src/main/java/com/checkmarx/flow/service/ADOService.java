package com.checkmarx.flow.service;

import com.checkmarx.flow.config.ADOProperties;
import com.checkmarx.flow.config.FlowProperties;
import com.checkmarx.flow.dto.ScanRequest;
import com.checkmarx.flow.dto.azure.CreateWorkItemAttr;
import com.checkmarx.flow.exception.ADOClientException;
import com.checkmarx.flow.utils.ScanUtils;
import com.checkmarx.sdk.dto.ScanResults;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.beans.ConstructorProperties;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Service
public class ADOService {
    private static final Logger log = LoggerFactory.getLogger(ADOService.class);
    private final RestTemplate restTemplate;
    private final ADOProperties properties;
    private final FlowProperties flowProperties;

    @ConstructorProperties({"restTemplate", "properties", "flowProperties"})
    public ADOService(@Qualifier("flowRestTemplate") RestTemplate restTemplate, ADOProperties properties, FlowProperties flowProperties) {
        this.restTemplate = restTemplate;
        this.properties = properties;
        this.flowProperties = flowProperties;
    }

    private HttpHeaders createAuthHeaders(){
        String encoding = Base64.getEncoder().encodeToString(":".concat(properties.getToken()).getBytes());
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.set("Content-Type", "application/json");
        httpHeaders.set("Authorization", "Basic ".concat(encoding));
        httpHeaders.set("Accept", "application/json");
        return httpHeaders;
    }

    private HttpHeaders createPatchAuthHeaders(){
        HttpHeaders httpHeaders = createAuthHeaders();
        httpHeaders.set("Content-Type", "application/json-patch+json");
        return httpHeaders;
    }

    void processPull(ScanRequest request, ScanResults results) throws ADOClientException {
        try {
            String comment = ScanUtils.getMergeCommentMD(request, results, flowProperties, properties);
            log.debug("comment: {}", comment);
            sendMergeComment(request, comment);
        } catch (HttpClientErrorException e){
            log.error("Error occurred while creating Merge Request comment");
            throw new ADOClientException();
        }
    }

    void sendMergeComment(ScanRequest request, String comment){
        String mergeUrl = request.getMergeNoteUri();
        if(ScanUtils.empty(mergeUrl)){
            log.error("mergeUrl was not provided within the request object, which is required for commenting on pull request");
            return;
        }
        log.debug(mergeUrl);
        String threadId = request.getAdditionalMetadata("ado_thread_id");
        if(ScanUtils.empty(threadId)){
            HttpEntity httpEntity = new HttpEntity<>(getJSONThread(comment).toString(), createAuthHeaders());
            log.debug("Creating new thread for comments");
            ResponseEntity<String> response = restTemplate.exchange(mergeUrl.concat("?api-version=").concat(properties.getApiVersion()),
                    HttpMethod.POST, httpEntity, String.class);
            if(response.getBody() != null) {
                JSONObject json = new JSONObject(response.getBody());
                int id = json.getInt("id");
                request.putAdditionalMetadata("ado_thread_id", Integer.toString(id));
                log.debug("Created new thread with Id {}", id);
            }
        }
        else{
            HttpEntity httpEntity = new HttpEntity<>(getJSONComment(comment).toString(), createAuthHeaders());
            mergeUrl = mergeUrl.concat("/").concat(threadId).concat("/comments");
            log.debug("Adding comment to thread Id {}", threadId);
            restTemplate.exchange(mergeUrl.concat("?api-version=").concat(properties.getApiVersion()),
                    HttpMethod.POST, httpEntity, String.class);
        }
    }

    void startBlockMerge(ScanRequest request){
        if(properties.isBlockMerge()) {
            String url = request.getAdditionalMetadata("statuses_url");
            if(url == null){
                log.warn("No status url found, skipping status update");
                return;
            }
            HttpEntity httpEntity = new HttpEntity<>(
                    getJSONStatus("pending", url, "Checkmarx Scan Initiated").toString(),
                    createAuthHeaders()
            );
            if(ScanUtils.empty(url)){
                log.error("statuses_url was not provided within the request object, which is required for blocking / unblocking pull requests");
                return;
            }
            //TODO remove preview once applicable
            log.info("Adding pending status to pull {}", url);
            ResponseEntity response = restTemplate.exchange(url.concat("?api-version=").concat(properties.getApiVersion().concat("-preview")),
                    HttpMethod.POST, httpEntity, String.class);
            if(response.getBody() != null) {
                JSONObject json = new JSONObject((String) response.getBody());
                int id = json.getInt("id");
                request.getAdditionalMetadata().put("status_id", Integer.toString(id));
            }
            log.debug(response.getStatusCode().toString());
        }
    }

    void endBlockMerge(ScanRequest request){
        if(properties.isBlockMerge()) {
            String url = request.getAdditionalMetadata("statuses_url");
            String statusId = request.getAdditionalMetadata("status_id");
            if(statusId == null){
                log.warn("No status Id found, skipping status update");
                return;
            }
            CreateWorkItemAttr item = new CreateWorkItemAttr();
            item.setOp("remove");
            item.setPath("/".concat(statusId));
            List<CreateWorkItemAttr> list = new ArrayList<>();
            list.add(item);

            HttpEntity<List<CreateWorkItemAttr>> httpEntity = new HttpEntity<>(
                    list,
                    createPatchAuthHeaders()
            );
            if(ScanUtils.empty(url)){
                log.error("statuses_url was not provided within the request object, which is required for blocking / unblocking pull requests");
                return;
            }
            //TODO remove preview once applicable
            log.info("Removing pending status from pull {}", url);
            restTemplate.exchange(url.concat("?api-version=").concat(properties.getApiVersion().concat("-preview")),
                    HttpMethod.PATCH, httpEntity, Void.class);
        }
    }

    //TODO
    void failBlockMerge(ScanRequest request, String url){

        if(properties.isBlockMerge()) {
            HttpEntity httpEntity = new HttpEntity<>(
                    getJSONStatus("failed", url, "Checkmarx Issue Threshold exceeded").toString(),
                    createAuthHeaders()
            );
            if(ScanUtils.empty(request.getAdditionalMetadata("statuses_url"))){
                log.error("statuses_url was not provided within the request object, which is required for blocking / unblocking pull requests");
                return;
            }
            restTemplate.exchange(request.getAdditionalMetadata("statuses_url"),
                    HttpMethod.POST, httpEntity, String.class);
        }
    }

    private JSONObject getJSONStatus(String state, String url, String description){
        JSONObject requestBody = new JSONObject();
        JSONObject context = new JSONObject();
        requestBody.put("state", state);
        requestBody.put("description", description);
        context.put("name", "checkmarx");
        context.put("genre", "sast");
        requestBody.put("context", context);
        requestBody.put("target_url", url);
        return requestBody;
    }
/*
{
  "state": "succeeded", | succeeded, failed, pending, notSet, notApplicable | error
  "description": "Sample status succeeded",
  "context": {
    "name": "sample-status-4",
    "genre": "vsts-samples"
  },
  "targetUrl": "http://fabrikam-fiber-inc.com/CI/builds/1"
}
*/
    private JSONObject getJSONThread(String description){
        JSONObject requestBody = new JSONObject();
        JSONArray comments = new JSONArray();
        JSONObject comment = new JSONObject();
        comment.put("parentCommentId", 0);
        comment.put("content", description);
        comment.put("commentType", 1);
        comments.put(comment);
        requestBody.put("comments", comments);
        requestBody.put("status", 1);

        return requestBody;
    }

    private JSONObject getJSONComment(String description){
        JSONObject requestBody = new JSONObject();
        requestBody.put("content", description);
        requestBody.put("parentCommentId", 1);
        requestBody.put("commentType", 1);

        return requestBody;
    }
    /*
    {
  "comments": [
    {
      "parentCommentId": 0,
      "content": "This new feature looks good!",
      "commentType": 1
    }
  ],
  "status": 1
}
 */
}