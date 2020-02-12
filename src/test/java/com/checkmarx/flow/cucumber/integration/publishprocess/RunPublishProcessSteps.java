package com.checkmarx.flow.cucumber.integration.publishprocess;

import com.checkmarx.flow.CxFlowApplication;
import com.checkmarx.flow.config.FlowProperties;
import com.checkmarx.flow.config.JiraProperties;
import com.checkmarx.flow.dto.BugTracker;
import com.checkmarx.flow.dto.ScanRequest;
import com.checkmarx.flow.exception.ExitThrowable;
import com.checkmarx.flow.service.FlowService;
import com.checkmarx.jira.IJiraTestUtils;
import com.checkmarx.jira.JiraTestUtils;
import com.checkmarx.sdk.config.Constants;
import com.checkmarx.sdk.config.CxProperties;
import com.checkmarx.sdk.dto.Filter;
import io.cucumber.java.Before;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.junit.Assert;

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

@SpringBootTest(classes = {CxFlowApplication.class, JiraTestUtils.class})
public class RunPublishProcessSteps {

    private final static String JIRA_PROJECT_KEY = "APPSEC";

    private BugTracker.Type bugTracker;

    private int numOfFindings;

    private static final String DIFFERENT_VULNERABILITIES_FILENAME_TEMPLATE = "cucumber/data/sample-sast-results/%d-findings-different-vuln-type-same-file.xml";
    private static final String SAME_VULNERABILITIES_FILENAME_TEMPLATE = "cucumber/data/sample-sast-results/%d-findings-same-vuln-type-same-file.xml";

    @Autowired
    private IJiraTestUtils jiraUtils;

    @Autowired
    private FlowService flowService;

    @Autowired
    private FlowProperties flowProperties;

    @Autowired
    private CxProperties cxProperties;

    @Autowired
    private JiraProperties jiraProperties;

    private FindingsType findingsType;

    private List<Filter> filters;

    private boolean needFilter;

    private int totalResults;

    private boolean useSanityFindingsFile = false;

    private List<Filter.Type>  severityFilterTypes = new ArrayList<>();

    @Before("@PublishProcessing")
    public void setDefaults() {
        needFilter = false;
        useSanityFindingsFile = false;
    }

    @Before("@PublishProcessing")
    public void setOfflineMode() {
        cxProperties.setOffline(true);
    }

    @Before("@PublishProcessing")
    public void cleanJiraProject() throws IOException {
        jiraUtils.ensureProjectExists(jiraProperties.getProject());
        //jiraUtils.ensureIssueTypeExists(jiraProperties.getIssueType());
        jiraUtils.cleanProject(jiraProperties.getProject());
    }

    @Given("target is JIRA")
    public void setTargetTypeToJira() {
        bugTracker = BugTracker.Type.JIRA;
    }

    @Given("there are {int} results from which {int} results match the filter")
    public void setResultsAndFilters(int totalResults, int matchingResults) {
        findingsType = FindingsType.DIFFERENT_SEVERITIES;
        numOfFindings = matchingResults;
        this.totalResults = totalResults;
        needFilter = true;
        Filter filter = Filter.builder().type(Filter.Type.SEVERITY).value("High").build();
        filters =Arrays.asList(filter);
    }

    @Given("filter-severity is {}")
    public void setSeverityFilterTypes(String types) {
        filters = createFiltersFromString(types, Filter.Type.SEVERITY);
        needFilter = true;
    }

    @Given("using sanity findings")
    public void setUseSanityFindingsFile() {
        useSanityFindingsFile = true;
    }


    @When("publishing results to JIRA")
    public void publishResults() throws ExitThrowable, IOException {
        ScanRequest request = getScanRequestWithDefaults();
        if (needFilter) {
            request.setFilters(filters);
        }
        request.setBugTracker(createJiraBugTracker());
        flowProperties.setBugTracker(bugTracker.name());
        flowService.cxParseResults(request, getFileForFindingsNum());
    }

    @When("results contain {} findings each having a different vulnerability type in one source file")
    public void setNumberOfFindingsForTest(int numOfFindings) {
        this.numOfFindings = numOfFindings;
        findingsType = FindingsType.DIFFERENT_TYPE;
    }

    @When("results contains {int} findings with the same type")
    public void getFindingsFileWithSameTypeVulnerabilities(int findings) {
        numOfFindings = findings;
        findingsType = FindingsType.SAME_TYPE;
    }
    @Then("verify results contains {int}, {int}, {int}, {int} for severities {}")
    public void verifyNumOfIssuesForSeverities(int high, int medium, int low, int info, String severities) {
        List<Filter> filters = createFiltersFromString(severities, Filter.Type.SEVERITY);
        Map<Filter.Severity, Integer> actualJira = jiraUtils.getIssuesPerSeverity(JIRA_PROJECT_KEY);
        for (Filter filter: filters) {
            Filter.Severity severity = Filter.Severity.valueOf(filter.getValue().toUpperCase());
            switch (severity) {
                case HIGH:
                    Assert.assertEquals("HIGH issues does not match", (int) actualJira.get(Filter.Severity.HIGH), high);
                    break;
                case MEDIUM:
                    Assert.assertEquals("Medium issues does not match", (int) actualJira.get(Filter.Severity.MEDIUM), medium);
                    break;
                case LOW:
                    Assert.assertEquals("Medium issues does not match", (int) actualJira.get(Filter.Severity.LOW), low);
                    break;
                case INFO:
                    Assert.assertEquals("Medium issues does not match", (int) actualJira.get(Filter.Severity.INFO), info);
                    break;
            }
        }
    }

    @Then("verify {int} new issues got created")
    public void verifyNumberOfIssues(int wantedNumOfIssues) {
        int actualNumOfIssues = jiraUtils.getNumberOfIssuesInProject(JIRA_PROJECT_KEY);
        Assert.assertEquals("Wrong number of issues in JIRA", wantedNumOfIssues,  actualNumOfIssues);
    }


    @Then("verify {int} findings in body")
    public void verifyNumOfFindingsInBodyForOneIssue(int findings) {
        int actualFindings = jiraUtils.getFirstIssueNוumOfFindings(JIRA_PROJECT_KEY);
        Assert.assertEquals("Wrong number of findigs", findings, actualFindings);
    }

    private ScanRequest getScanRequestWithDefaults() {
        ScanRequest request = ScanRequest.builder()
                .application("App1")
                .product(ScanRequest.Product.CX)
                .project("CodeInjection1")
                .team("CxServer")
                .namespace("compTest")
                .repoName("repo")
                .repoUrl("http://localhost/repo.git")
                .repoUrlWithAuth("http://localhost/repo.git")
                .repoType(ScanRequest.Repository.NA)
                .branch("master")
                .refs(Constants.CX_BRANCH_PREFIX.concat("master"))
                .email(null)
                .incremental(false)
                .scanPreset("Checkmarx Default")
                .build();
        return request;
    }

    private File getDifferentVulnerabilityTypeFindings() throws IOException {
            return getFileFromResourcePath(String.format(DIFFERENT_VULNERABILITIES_FILENAME_TEMPLATE, numOfFindings));
    }

    private File getSameVulnerabilityTypeFindings() throws IOException {
        return getFileFromResourcePath(String.format(SAME_VULNERABILITIES_FILENAME_TEMPLATE, numOfFindings));
    }

    private File getDifferentSeveritiesFindings() throws IOException {
        if (numOfFindings ==1 && totalResults == 3) {
            return getFileFromResourcePath("cucumber/data/sample-sast-results/3-findings-different-severity-medium-high-critical.xml");
        }
        if (numOfFindings == 5 && totalResults == 10) {
            return getFileFromResourcePath("cucumber/data/sample-sast-results/different-severities-10-5.xml");
        }
        if (numOfFindings == 10 && totalResults == 10) {
            return getFileFromResourcePath("cucumber/data/sample-sast-results/different-severities-10-10.xml");
        }
        return null;
    }

    private List<Filter> createFiltersFromString(String filterValue, Filter.Type type) {
        if (StringUtils.isEmpty(filterValue)) {
            return Collections.emptyList();
        }
        String[] filterValArr = filterValue.split(",");
        return Arrays.stream(filterValArr).map(filterVal -> new Filter(type, filterVal)).collect(Collectors.toList());
    }


    private File getFileForFindingsNum() throws IOException {
        if (useSanityFindingsFile) {
            return getFileFromResourcePath("cucumber/data/sample-sast-results/findings-sanity.xml");
        }
        if (numOfFindings == 0) {
            return getFileFromResourcePath("cucumber/data/sample-sast-results/empty-results.xml");
        }
        if (numOfFindings == 1) {
            return getFileFromResourcePath("cucumber/data/sample-sast-results/1-finding.xml");
        }
        switch (findingsType) {
            case SAME_TYPE:
                return getSameVulnerabilityTypeFindings();
            case DIFFERENT_TYPE:
                return getDifferentVulnerabilityTypeFindings();
            case DIFFERENT_SEVERITIES:
                return getDifferentSeveritiesFindings();
            default:
                return null;
        }
    }

    private File getDifferentSeverities() throws IOException {
        return getFileFromResourcePath("cucumber/data/sample-sast-results/3-findings-different-severity-medium-high-critical.xml");
    }


    public File getFileFromResourcePath(String path) throws IOException {
        return new ClassPathResource(path).getFile();
    }

    private BugTracker createJiraBugTracker() {
        BugTracker bt = BugTracker.builder()
                .issueType(jiraProperties.getIssueType())
                .projectKey(jiraProperties.getProject())
                .type(BugTracker.Type.JIRA)
                .build();
        return bt;
    }


    enum FindingsType {
        SAME_TYPE,
        DIFFERENT_TYPE,
        DIFFERENT_SEVERITIES
    }

}
