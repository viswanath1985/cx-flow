package com.custodela.machina.service;

import com.custodela.machina.custom.IssueTracker;
import com.custodela.machina.dto.BugTracker;
import com.custodela.machina.dto.ScanRequest;
import com.custodela.machina.dto.ScanResults;
import com.custodela.machina.dto.Issue;
import com.custodela.machina.exception.MachinaException;
import com.custodela.machina.exception.MachinaRuntimeException;
import com.custodela.machina.utils.ScanUtils;
import org.slf4j.Logger;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.web.client.HttpClientErrorException;
import java.util.*;


public class IssueService implements ApplicationContextAware {

    private ApplicationContext context;
    private static final Logger log = org.slf4j.LoggerFactory.getLogger(IssueService.class);


    public ApplicationContext getContext() {
        return context;
    }

    @Override
    public void setApplicationContext(ApplicationContext context){
        this.context = context;
    }

    /**
     * Creates a map of GitLab Issues
     *
     * @param issues
     * @return
     */
    private Map<String, Issue> getIssueMap(IssueTracker tracker, List<Issue> issues, ScanRequest request) {
        Map<String, Issue> issueMap = new HashMap<>();
        for (Issue issue : issues) {
            String key = tracker.getIssueKey(issue, request);
            issueMap.put(key, issue);
        }
        return issueMap;
    }

    private Map<String, ScanResults.XIssue> getXIssueMap(IssueTracker tracker, List<ScanResults.XIssue> issues, ScanRequest request) {
        Map<String, ScanResults.XIssue> xMap = new HashMap<>();
        for (ScanResults.XIssue issue : issues) {
            String key = tracker.getXIssueKey(issue, request);
            xMap.put(key, issue);
        }
        return xMap;
    }

    Map<String, List<String>> process(ScanResults results, ScanRequest request) throws MachinaException {
        Map<String, ScanResults.XIssue> xMap;
        Map<String, Issue> iMap;
        List<String> newIssues = new ArrayList<>();
        List<String> updatedIssues = new ArrayList<>();
        List<String> closedIssues = new ArrayList<>();
        if (!request.getBugTracker().getType().equals(BugTracker.Type.CUSTOM) && !ScanUtils.empty(request.getBugTracker().getCustomBean())) {
            throw new MachinaException("Custom  bean must be used here.");
        }
        try {
            IssueTracker tracker = (IssueTracker) context.getBean(request.getBugTracker().getCustomBean());
            String fpLabel = tracker.getFalsePositiveLabel();

            log.info("Processing Issues with custom bean {}", request.getBugTracker().getCustomBean());

            List<Issue> issues = tracker.getIssues(request);
            xMap = this.getXIssueMap(tracker, results.getXIssues(), request);
            iMap = this.getIssueMap(tracker, issues, request);

            for (Map.Entry<String, ScanResults.XIssue> xIssue : xMap.entrySet()) {
                try {
                    String fileUrl;
                    ScanResults.XIssue currentIssue = xIssue.getValue();

                    /*Issue already exists -> update and comment*/
                    if (iMap.containsKey(xIssue.getKey())) {
                        Issue i = iMap.get(xIssue.getKey());

                        /*Ignore any with label indicating false positive*/
                        if (!i.getLabels().contains(fpLabel)) {
                            log.info("Issue still exists.  Updating issue with key {}", xIssue.getKey());
                            fileUrl = ScanUtils.getFileUrl(request, currentIssue.getFilename());
                            currentIssue.setGitUrl(fileUrl);
                            Issue updatedIssue = tracker.updateIssue(i, currentIssue);
                            if (updatedIssue != null) {
                                updatedIssues.add(updatedIssue.getId());
                                log.debug("Update completed for issue #{}", updatedIssue.getId());
                            }
                        } else {
                            log.info("Skipping issue marked as false positive with key {}", xIssue.getKey());
                        }
                    } else {
                        /*Create the new issue*/
                        fileUrl = ScanUtils.getFileUrl(request, currentIssue.getFilename());
                        xIssue.getValue().setGitUrl(fileUrl);
                        log.info("Creating new issue with key {}", xIssue.getKey());
                        Issue newIssue = tracker.createIssue(xIssue.getValue(), request);
                        newIssues.add(newIssue.getId());
                        log.info("New issue created. #{}", newIssue.getId());
                    }
                } catch (HttpClientErrorException e) {
                    log.error("Error occurred while processing issue with key {} {}", xIssue.getKey(), e);
                }
            }

            /*Check if an issue exists in GitLab but not within results and close if not*/
            for (Map.Entry<String, Issue> issue : iMap.entrySet()) {
                try {
                    if (!xMap.containsKey(issue.getKey())) {
                        if (issue.getValue().getState().equals("opened")) {
                            /*Close the issue*/
                            closedIssues.add(issue.getValue().getId());
                            log.info("Closing issue #{} with key {}", issue.getValue().getId(), issue.getKey());
                            tracker.closeIssue(issue.getValue(), request);
                        }
                    }
                } catch (HttpClientErrorException e) {
                    log.error("Error occurred while processing issue with key {} {}", issue.getKey(), e);
                }
            }

            Map<String, List<String>> issuesMap = new HashMap<>();
            issuesMap.put("new", newIssues);
            issuesMap.put("updated", updatedIssues);
            issuesMap.put("closed", closedIssues);
            return issuesMap;
        } catch (BeansException e){
            log.error("Specified bug tracker bean was not found or properly loaded.");
            throw new MachinaRuntimeException();
        } catch (ClassCastException e){
            log.error("Bean must implement the IssueTracker Interface");
            throw new MachinaRuntimeException();
        }
    }

}
