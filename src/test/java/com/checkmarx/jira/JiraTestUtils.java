package com.checkmarx.jira;

import com.atlassian.jira.rest.client.api.JiraRestClient;
import com.atlassian.jira.rest.client.api.domain.Issue;
import com.atlassian.jira.rest.client.api.domain.SearchResult;
import com.atlassian.jira.rest.client.internal.async.CustomAsynchronousJiraRestClientFactory;
import com.checkmarx.flow.config.JiraProperties;
import com.checkmarx.flow.utils.ScanUtils;
import com.checkmarx.sdk.dto.Filter;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestComponent;
import org.springframework.http.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


@TestComponent
public class JiraTestUtils implements IJiraTestUtils {
    private static final Logger log = LoggerFactory.getLogger(JiraTestUtils.class);

    private static final String JIRA_DESCRIPTION_FINDING_LINE = "[Line #";

    private JiraRestClient client;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    private JiraProperties jiraProperties;

    @PostConstruct
    public void initClient() {
        if (jiraProperties != null && !ScanUtils.empty(jiraProperties.getUrl())) {
            CustomAsynchronousJiraRestClientFactory factory = new CustomAsynchronousJiraRestClientFactory();
            URI jiraURI = null;
            try {
                jiraURI = new URI(jiraProperties.getUrl());
            } catch (URISyntaxException e) {
                //log.error("Error constructing URI for JIRA", e);
            }
            this.client = factory.createWithBasicHttpAuthenticationCustom(jiraURI, jiraProperties.getUsername(), jiraProperties.getToken(), jiraProperties.getHttpTimeout());

        }
    }

    @Override
    public void deleteIssue(String issueKey) {
        client.getIssueClient().deleteIssue(issueKey, true).claim();
    }

    private SearchResult search(String jql) {
        return  client.getSearchClient().searchJql(jql).claim();
    }

    @Override
    public void cleanProject(String projectKey) {
        SearchResult searchResult = search(String.format("project = \"%s\"", projectKey));
        for (Issue issue: searchResult.getIssues()) {
            deleteIssue(issue.getKey());
        }
    }

    @Override
    public int getNumberOfIssuesInProject(String projectKey) {
        SearchResult result = search(String.format("project = \"%s\"", projectKey));
        return result.getTotal();
    }

    @Override
    public Map<Filter.Severity, Integer> getIssuesPerSeverity(String projectKey) {
        Map<Filter.Severity, Integer> result= new HashMap<>();
        SearchResult searchResults = search(String.format("project = \"%s\"", projectKey));
        for (Issue issue: searchResults.getIssues()) {
            String severity = getIssueSeverity(issue.getDescription()).toUpperCase();
            Filter.Severity filterSeverity = Filter.Severity.valueOf(severity.toUpperCase());
            if (severity != null) {
                if (result.containsKey(filterSeverity)) {
                    result.put(filterSeverity,result.get(filterSeverity) + 1 );
                } else {
                    result.put(filterSeverity, 1);
                }
            }
        }
        return result;
    }

    private String getIssueSeverity(String issueDescription) {
        String[] lines = issueDescription.split(System.lineSeparator());
        for (String line: lines) {
            if (line.contains("Severity:")) {
                return line.split(" ")[1];
            }
        }
        return null;
    }


    @Override
    public int getFirstIssueNוumOfFindings(String projectKey) {
        SearchResult result = search(String.format("project = \"%s\"", projectKey));
        if (result.getTotal() ==0) {
            return 0;
        }
        Issue i = result.getIssues().iterator().next();
        int lastIndex = 0;
        int count = 0;
        while (lastIndex != -1) {
            lastIndex = i.getDescription().indexOf(JIRA_DESCRIPTION_FINDING_LINE, lastIndex);
            if (lastIndex != -1) {
                count++;
                lastIndex += JIRA_DESCRIPTION_FINDING_LINE.length();
            }
        }
        return count;
    }
    @Override
    public void ensureProjectExists(String key) throws IOException {
        log.info("Making sure '{}' project exists in Jira.", key);
        ResourceCreationConfig config = getProjectCreationConfig(key);
        tryCreateResource(config);
    }

    @Override
    public void ensureIssueTypeExists(String issueType) throws IOException {
        log.info("Making sure '{}' issue type exists in Jira.", issueType);
        ResourceCreationConfig config = getIssueCreationConfig(issueType);
        tryCreateResource(config);
    }

    @Override
    public String getIssuePriority(String projectKey) {
        Issue issue = getFirstIssue(projectKey);
        return issue.getPriority().getName();
    }

    @Override
    public Long getIssueUpdatedTime(String projectKey) {
        Issue issue = getFirstIssue(projectKey);
        return issue.getUpdateDate().getMillis();
    }

    @Override
    public String getIssueStatus(String projectKey) {
        Issue issue = getFirstIssue(projectKey);
        return issue.getStatus().getName();
    }

    private ResourceCreationConfig getIssueCreationConfig(String issueType) {
        ResourceCreationConfig config = new ResourceCreationConfig();
        config.body = getIssueTypeRequestBody(issueType);
        config.resourceName = "issuetype";
        config.expectedErrorStatus = HttpStatus.CONFLICT;
        config.errorFieldName = "name";
        config.errorFieldValue = "An issue type with this name already exists.";
        return config;
    }

    private ResourceCreationConfig getProjectCreationConfig(String key) throws JsonProcessingException {
        ResourceCreationConfig config = new ResourceCreationConfig();
        config.body = getProjectRequestBody(key);
        config.resourceName = "project";
        config.expectedErrorStatus = HttpStatus.BAD_REQUEST;
        config.errorFieldName = "projectName";
        config.errorFieldValue = "A project with that name already exists.";
        return config;
    }

    private void tryCreateResource(ResourceCreationConfig config)
            throws IOException {
        boolean alreadyExists = false, createdSuccessfully = false;
        try {
            ResponseEntity<JsonNode> response = sendCreationRequest(config);
            createdSuccessfully = isResourceCreatedSuccessfully(response);
        } catch (Exception e) {
            alreadyExists = doesResourceAlreadyExist(e, config);
        }

        if (createdSuccessfully) {
            log.info("{} created successfully.", config.resourceName);
        } else if (alreadyExists) {
            log.info("{} already exists", config.resourceName);
        }

        if (!createdSuccessfully && !alreadyExists) {
            throw new IOException("Unable to create " + config.resourceName);
        }
    }

    private ObjectNode getIssueTypeRequestBody(String issueType) {
        return objectMapper.createObjectNode()
                .put("name", issueType)
                .put("type", "standard");
    }

    private boolean isResourceCreatedSuccessfully(ResponseEntity<JsonNode> response) {
        return response != null && response.getStatusCode() == HttpStatus.CREATED;
    }

    private boolean doesResourceAlreadyExist(Exception exception, ResourceCreationConfig config) {
        boolean result = false;
        if (exception instanceof HttpClientErrorException) {
            HttpClientErrorException clientException = (HttpClientErrorException) exception;
            result = clientException.getStatusCode() == config.expectedErrorStatus &&
                    containsExpectedErrorMessage(clientException, config);
        }
        return result;
    }

    private boolean containsExpectedErrorMessage(HttpClientErrorException exception, ResourceCreationConfig config) {
        boolean result = false;
        try {
            JsonNode response = objectMapper.readTree(exception.getResponseBodyAsByteArray());
            result = response.at("/errors/" + config.errorFieldName)
                    .asText()
                    // Checking text: less reliable, but saves us an additional API call.
                    .equals(config.errorFieldValue);

        } catch (IOException ex) { /* Ignored */ }
        return result;
    }

    private ResponseEntity<JsonNode> sendCreationRequest(ResourceCreationConfig config)
            throws URISyntaxException {
        URI fullUri = new URI(jiraProperties.getUrl())
                .resolve("/rest/api/2/" + config.resourceName);

        HttpEntity<ObjectNode> request = new HttpEntity<>(config.body, config.headers);

        RestTemplate client = new RestTemplate();
        return client.exchange(fullUri, HttpMethod.POST, request, JsonNode.class);
    }

    private ObjectNode getProjectRequestBody(String key) throws JsonProcessingException {
        final String REQUEST_TEMPLATE = ("{" +
                " 'projectTypeKey': 'software'," +
                " 'projectTemplateKey': 'com.pyxis.greenhopper.jira:gh-scrum-template'," +
                " 'description': 'Automation'," +
                " 'lead': 'admin'," +
                " 'assigneeType': 'PROJECT_LEAD'," +
                " 'avatarId': 10200" +
                " }")
                .replace("'", "\"");

        ObjectNode body = (ObjectNode) objectMapper.readTree(REQUEST_TEMPLATE);

        body.put("key", key)
                .put("name", key);
        return body;
    }

    private HttpHeaders getHeaders() {
        String credentials = String.format("%s:%s", jiraProperties.getUsername(), jiraProperties.getToken());
        String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());

        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        headers.set(HttpHeaders.AUTHORIZATION, "Basic " + encodedCredentials);
        headers.set(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
        return headers;
    }

    // Added to avoid passing too many method args.
    private class ResourceCreationConfig {
        public final HttpHeaders headers = getHeaders();
        public ObjectNode body;
        public String resourceName;
        public String errorFieldName;
        public String errorFieldValue;
        public HttpStatus expectedErrorStatus;
    }

    private Issue getFirstIssue(String projectKey) {
        SearchResult result = search(String.format("project = \"%s\"", projectKey));
        if (result.getTotal() == 0) {
            // TODO throw some exception that nakes sense
            return null;
        }
        return result.getIssues().iterator().next();
    }
}
