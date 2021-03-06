package com.checkmarx.flow.service;

import com.checkmarx.flow.config.FlowProperties;
import com.checkmarx.flow.dto.BugTracker;
import com.checkmarx.flow.dto.ScanRequest;
import com.checkmarx.flow.dto.Sources;
import com.checkmarx.flow.exception.MachinaException;
import com.checkmarx.flow.utils.ScanUtils;
import com.checkmarx.flow.utils.ZipUtils;
import com.checkmarx.sdk.config.Constants;
import com.checkmarx.sdk.config.CxProperties;
import com.checkmarx.sdk.dto.ScanResults;
import com.checkmarx.sdk.dto.cx.CxProject;
import com.checkmarx.sdk.dto.cx.CxScanParams;
import com.checkmarx.sdk.exception.CheckmarxException;
import com.checkmarx.sdk.service.CxClient;
import com.checkmarx.sdk.service.CxOsaClient;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.slf4j.Logger;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.util.*;
import java.util.concurrent.CompletableFuture;

import static com.checkmarx.sdk.config.Constants.UNKNOWN;
import static com.checkmarx.sdk.config.Constants.UNKNOWN_INT;
import static java.lang.System.exit;

@Service
public class FlowService {

    private static final Logger log = org.slf4j.LoggerFactory.getLogger(FlowService.class);

    private static final String SCAN_MESSAGE = "Scan submitted to Checkmarx";
    private final CxClient cxService;
    private final CxOsaClient osaService;
    private final GitHubService gitService;
    private final GitLabService gitLabService;
    private final BitBucketService bbService;
    private final ADOService adoService;
    private final EmailService emailService;
    private final CxProperties cxProperties;
    private final FlowProperties flowProperties;
    private final ResultsService resultsService;
    private final HelperService helperService;
    private static final Long SLEEP = 20000L;
    private static final String ERROR_BREAK_MSG = "Exiting with Error code 10 due to issues present";

    public FlowService(CxClient cxService, CxOsaClient osaService, ResultsService resultsService, GitHubService gitService,
                       GitLabService gitLabService, BitBucketService bbService, ADOService adoService,
                       EmailService emailService, HelperService helperService, CxProperties cxProperties,
                       FlowProperties flowProperties) {
        this.cxService = cxService;
        this.osaService = osaService;
        this.resultsService = resultsService;
        this.gitService = gitService;
        this.gitLabService = gitLabService;
        this.bbService = bbService;
        this.adoService = adoService;
        this.emailService = emailService;
        this.helperService = helperService;
        this.cxProperties = cxProperties;
        this.flowProperties = flowProperties;
    }

    @Async("webHook")
    public void initiateAutomation(ScanRequest request) {
        Map<String, Object>  emailCtx = new HashMap<>();
        try {
            if (request.getProduct().equals(ScanRequest.Product.CX)) {
                if(!ScanUtils.anyEmpty(request.getNamespace(), request.getRepoName(), request.getRepoUrl())) {
                    emailCtx.put("message", "Checkmarx Scan has been submitted for "
                            .concat(request.getNamespace()).concat("/").concat(request.getRepoName()).concat(" - ")
                            .concat(request.getRepoUrl()));
                    emailCtx.put("heading", "Scan Request Submitted");
                    emailService.sendmail(request.getEmail(), "Checkmarx Scan Submitted for ".concat(request.getNamespace()).concat("/").concat(request.getRepoName()), emailCtx, "message.html");
                }
                CompletableFuture<ScanResults> results = executeCxScanFlow(request, null);
                if(results.isCompletedExceptionally()){
                    log.error("An error occurred while executing process");
                }
            } else {
                log.warn("Unknown Product type of {}, exiting", request.getProduct());
            }
        } catch (MachinaException e){
            log.error("Machina Exception has occurred.  {}", ExceptionUtils.getStackTrace(e));
            emailCtx.put("message", "Error occurred during scan/bug tracking process for "
                    .concat(request.getNamespace()).concat("/").concat(request.getRepoName()).concat(" - ")
                    .concat(request.getRepoUrl()).concat("  Error: ").concat(e.getMessage()));
            emailCtx.put("heading","Error occurred during scan");
            emailService.sendmail(request.getEmail(), "Error occurred for ".concat(request.getNamespace()).concat("/").concat(request.getRepoName()), emailCtx, "message-error.html");
        }
    }

    private CompletableFuture<ScanResults> executeCxScanFlow(ScanRequest request, File cxFile) throws MachinaException {
        try {
            String ownerId;
            String projectName;
            String repoName = request.getRepoName();
            String branch = request.getBranch();
            String namespace = request.getNamespace();

            /*Check if team is provided*/
            String team = helperService.getCxTeam(request);
            if(!ScanUtils.empty(team)){
                if(!team.startsWith(cxProperties.getTeamPathSeparator()))
                    team = cxProperties.getTeamPathSeparator().concat(team);
                log.info("Overriding team with {}", team);
                ownerId = cxService.getTeamId(team);
            }
            else{
                team = cxProperties.getTeam();
                if(!team.startsWith(cxProperties.getTeamPathSeparator()))
                    team = cxProperties.getTeamPathSeparator().concat(team);
                log.info("Using team {}", team);
                ownerId = cxService.getTeamId(team);

                if(cxProperties.isMultiTenant() &&
                        !ScanUtils.empty(namespace)){
                    String fullTeamName = cxProperties.getTeam().concat(cxProperties.getTeamPathSeparator()).concat(namespace);
                    request.setTeam(fullTeamName);
                    String tmpId = cxService.getTeamId(fullTeamName);
                    if(tmpId.equals(UNKNOWN)){
                        ownerId = cxService.createTeam(ownerId, namespace);
                    }
                    else{
                        ownerId = tmpId;
                    }
                }
                else{
                    request.setTeam(team);
                }
            }

            /*Determine project name*/
            String project = helperService.getCxProject(request);
            if(!ScanUtils.empty(project)){
                projectName = project;
            }
            else if(cxProperties.isMultiTenant() && !ScanUtils.empty(repoName)){
                projectName = repoName;
                if(!ScanUtils.empty(branch)){
                    projectName = projectName.concat("-").concat(branch);
                }
            }
            else{
                if(!ScanUtils.empty(namespace) && !ScanUtils.empty(repoName) && !ScanUtils.empty(branch)) {
                    projectName = namespace.concat("-").concat(repoName).concat("-").concat(branch);
                }
                else if(!ScanUtils.empty(request.getApplication())) {
                    projectName = request.getApplication();
                }
                else{
                    log.error("Namespace (--namespace)/RepoName(--repo-name)/Branch(--branch) OR Application (--app) must be provided if the Project is not provided (--cx-project)");
                    throw new MachinaException("Namespace (--namespace)/RepoName(--repo-name)/Branch(--branch) OR Application (--app) must be provided if the Project is not provided (--cx-project)") ;
                }
            }

            //Kick out if the team is unknown
            if(ownerId.equals(UNKNOWN)){
                throw new MachinaException("Parent team could not be established.  Please ensure correct team is provided");
            }
            //only allow specific chars in project name in checkmarx
            projectName = projectName.replaceAll("[^a-zA-Z0-9-_.]+","-");
            log.info("Project Name being used {}", projectName);
            Integer projectId = UNKNOWN_INT;
            if(flowProperties.isAutoProfile() && !request.isScanPresetOverride()) {
                boolean projectExists = false;
                projectId = cxService.getProjectId(ownerId, projectName);
                if(projectId != UNKNOWN_INT) {
                    int presetId = cxService.getProjectPresetId(projectId);
                    if(presetId != UNKNOWN_INT){
                        String preset = cxService.getPresetName(presetId);
                        request.setScanPreset(preset);
                        projectExists = true;
                    }
                }
                log.debug("Auto profiling is enabled");
                if(!projectExists || flowProperties.isAlwaysProfile()) {
                    log.info("Project is new, profiling source...");
                    Sources sources = new Sources();
                    switch (request.getRepoType()) {
                        case GITHUB:
                            sources = gitService.getRepoContent(request);
                            break;
                        case GITLAB:
                            sources = gitLabService.getRepoContent(request);
                            break;
                        case BITBUCKET:
                            log.warn("Profiling is not available for BitBucket Cloud");
                            break;
                        case BITBUCKETSERVER:
                            log.warn("Profiling is not available for BitBucket Server");
                            break;
                        case ADO:
                            log.warn("Profiling is not available for Azure DevOps");
                            break;
                        default:
                            break;
                    }
                    String preset = helperService.getPresetFromSources(sources);
                    if (!ScanUtils.empty(preset)) {
                        request.setScanPreset(preset);
                    }
                }
            }
            request.setProject(projectName);
            CxScanParams params = new CxScanParams()
                    .teamId(ownerId)
                    .withTeamName(request.getTeam())
                    .projectId(projectId)
                    .withProjectName(projectName)
                    .withScanPreset(request.getScanPreset())
                    .withGitUrl(request.getRepoUrlWithAuth())
                    .withIncremental(request.isIncremental())
                    .withForceScan(request.isForceScan())
                    .withFileExclude(request.getExcludeFiles())
                    .withFolderExclude(request.getExcludeFolders());
            if(!com.checkmarx.sdk.utils.ScanUtils.empty(request.getBranch())){
                params.withBranch(Constants.CX_BRANCH_PREFIX.concat(request.getBranch()));
            }
            if(cxFile != null){
                params.setSourceType(CxScanParams.Type.FILE);
                params.setFilePath(cxFile.getAbsolutePath());
            }
            BugTracker.Type bugTrackerType = request.getBugTracker().getType();
            if(bugTrackerType.equals(BugTracker.Type.GITLABMERGE)){
                gitLabService.sendMergeComment(request, SCAN_MESSAGE);
                gitLabService.startBlockMerge(request);
            }
            else if(bugTrackerType.equals(BugTracker.Type.GITLABCOMMIT)){
                gitLabService.sendCommitComment(request, SCAN_MESSAGE);
            }
            else if(bugTrackerType.equals(BugTracker.Type.GITHUBPULL)){
                gitService.sendMergeComment(request, SCAN_MESSAGE);
                gitService.startBlockMerge(request, cxProperties.getUrl());
            }
            else if(bugTrackerType.equals(BugTracker.Type.BITBUCKETPULL)){
                bbService.sendMergeComment(request, SCAN_MESSAGE);
            }
            else if(bugTrackerType.equals(BugTracker.Type.BITBUCKETSERVERPULL)){
                bbService.sendServerMergeComment(request, SCAN_MESSAGE);
            }
            else if(bugTrackerType.equals(BugTracker.Type.ADOPULL)){
                adoService.sendMergeComment(request, SCAN_MESSAGE);
                adoService.startBlockMerge(request);
            }

            Integer scanId = cxService.createScan(params,"CxFlow Automated Scan");

            if(bugTrackerType.equals(BugTracker.Type.NONE)){
                log.info("Not waiting for scan completion as Bug Tracker type is NONE");
                return CompletableFuture.completedFuture(null);
            }

            cxService.waitForScanCompletion(scanId);
            if(projectId == UNKNOWN_INT) {
                projectId = cxService.getProjectId(ownerId, projectName); //get the project id of the updated or created project
            }
            String osaScanId = null;
            if(cxProperties.getEnableOsa()){
                String path = cxProperties.getGitClonePath().concat("/").concat(UUID.randomUUID().toString());
                File pathFile = new File(path);

                Git git = Git.cloneRepository()
                        .setURI(request.getRepoUrlWithAuth())
                        .setBranch(request.getBranch())
                        .setBranchesToClone(Collections.singleton(Constants.CX_BRANCH_PREFIX.concat(request.getBranch()) ))
                        .setDirectory(pathFile)
                        .call();
                osaScanId = osaService.createScan(projectId, path);
            }
            return resultsService.processScanResultsAsync(request, projectId, scanId, osaScanId, request.getFilters());
        }catch (CheckmarxException | GitAPIException e){
            log.error(ExceptionUtils.getStackTrace(e));
            log.error(ExceptionUtils.getRootCauseMessage(e));
            Thread.currentThread().interrupt();
            throw new MachinaException("Checkmarx Error Occurred");
        }
    }

    public void cxFullScan(ScanRequest request, String path){

        try {
            String cxZipFile = FileSystems.getDefault().getPath("cx.".concat(UUID.randomUUID().toString()).concat(".zip")).toAbsolutePath().toString();
            ZipUtils.zipFile(path, cxZipFile, flowProperties.getZipExclude());
            File f = new File(cxZipFile);
            log.debug(f.getPath());
            log.debug("free space {}", f.getFreeSpace());
            log.debug("total space {}", f.getTotalSpace());
            log.debug(f.getAbsolutePath());
            CompletableFuture<ScanResults> future = executeCxScanFlow(request, f);
            log.debug("Waiting for scan to complete");
            ScanResults results = future.join();
            if(flowProperties.isBreakBuild() && results !=null && results.getXIssues()!=null && !results.getXIssues().isEmpty()){
                log.error(ERROR_BREAK_MSG);
                exit(10);
            }
        } catch (IOException e) {
            log.error(ExceptionUtils.getStackTrace(e));
            log.error("Error occurred while attempting to zip path {}", path);
            exit(3);
        } catch (MachinaException e){
            log.error(ExceptionUtils.getStackTrace(e));
            exit(3);
        }
    }

    public void cxFullScan(ScanRequest request){

        try {
            CompletableFuture<ScanResults> future = executeCxScanFlow(request, null);
            log.debug("Waiting for scan to complete");
            ScanResults results = future.join();
            if(flowProperties.isBreakBuild() && results !=null && results.getXIssues()!=null && !results.getXIssues().isEmpty()){
                log.error(ERROR_BREAK_MSG);
                exit(10);
            }
        } catch (MachinaException e){
            log.error(ExceptionUtils.getStackTrace(e));
            exit(3);
        }
    }


    public void cxParseResults(ScanRequest request, File file){
        try {
            ScanResults results = cxService.getReportContent(file, request.getFilters());
            resultsService.processResults(request, results);
            if(flowProperties.isBreakBuild() && results !=null && results.getXIssues()!=null && !results.getXIssues().isEmpty()){
                log.error(ERROR_BREAK_MSG);
                exit(10);
            }
        } catch (MachinaException | CheckmarxException e) {
            log.error(ExceptionUtils.getStackTrace(e));
            log.error("Error occurred while processing results file");
            exit(3);
        }
    }

    public void cxOsaParseResults(ScanRequest request, File file, File libs){
        try {
            ScanResults results = cxService.getOsaReportContent(file, libs, request.getFilters());
            resultsService.processResults(request, results);
            if(flowProperties.isBreakBuild() && results !=null && results.getXIssues()!=null && !results.getXIssues().isEmpty()){
                log.error(ERROR_BREAK_MSG);
                exit(10);
            }
        } catch (MachinaException | CheckmarxException e) {
            log.error(ExceptionUtils.getStackTrace(e));
            log.error("Error occurred while processing results file(s)");
            exit(3);
        }
    }


    public CompletableFuture<ScanResults> cxGetResults(ScanRequest request, CxProject cxProject){
        try {
            CxProject project;

            if(cxProject == null) {
                String team = request.getTeam();
                if(ScanUtils.empty(team)){
                    //if the team is not provided, use the default
                    team = cxProperties.getTeam();
                    request.setTeam(team);
                }
                if (!team.startsWith(cxProperties.getTeamPathSeparator())) {
                    team = cxProperties.getTeamPathSeparator().concat(team);
                }
                String teamId = cxService.getTeamId(team);
                Integer projectId = cxService.getProjectId(teamId, request.getProject());
                if(projectId.equals(UNKNOWN_INT)){
                    log.warn("No project found for {}", request.getProject());
                    CompletableFuture<ScanResults> x = new CompletableFuture<>();
                    x.complete(null);
                    return x;
                }
                project = cxService.getProject(projectId);

            }
            else {
                project = cxProject;
            }
            Integer scanId = cxService.getLastScanId(project.getId());
            if(scanId.equals(UNKNOWN_INT)){
                log.warn("No Scan Results to process for project {}", project.getName());
                CompletableFuture<ScanResults> x = new CompletableFuture<>();
                x.complete(null);
                return x;
            }
            else {
                getCxFields(project, request);
                //null is passed for osaScanId as it is not applicable here and will be ignored
                return resultsService.processScanResultsAsync(request, project.getId(), scanId, null, request.getFilters());
            }

        } catch (MachinaException | CheckmarxException e) {
            log.debug(ExceptionUtils.getStackTrace(e));
            log.error("Error occurred while processing results for {}{}", request.getTeam(), request.getProject());
            CompletableFuture<ScanResults> x = new CompletableFuture<>();
            x.completeExceptionally(e);
            return x;
        }
    }

    private void getCxFields(CxProject project, ScanRequest request) {
        if(project == null) { return; }

        Map<String, String> fields = new HashMap<>();
        for(CxProject.CustomField field : project.getCustomFields()){
            String name = field.getName();
            String value = field.getValue();
            if(!ScanUtils.empty(name) && !ScanUtils.empty(value)) {
                fields.put(name, value);
            }
        }
        if(!ScanUtils.empty(cxProperties.getJiraProjectField())){
            String jiraProject = fields.get(cxProperties.getJiraProjectField());
            if(!ScanUtils.empty(jiraProject)) {
                request.getBugTracker().setProjectKey(jiraProject);
            }
        }
        if(!ScanUtils.empty(cxProperties.getJiraIssuetypeField())) {
            String jiraIssuetype = fields.get(cxProperties.getJiraIssuetypeField());
            if (!ScanUtils.empty(jiraIssuetype)) {
                request.getBugTracker().setIssueType(jiraIssuetype);
            }
        }
        if(!ScanUtils.empty(cxProperties.getJiraCustomField()) &&
                (fields.get(cxProperties.getJiraCustomField()) != null) && !fields.get(cxProperties.getJiraCustomField()).isEmpty()){
            request.getBugTracker().setFields(ScanUtils.getCustomFieldsFromCx(fields.get(cxProperties.getJiraCustomField())));
        }

        if(!ScanUtils.empty(cxProperties.getJiraAssigneeField())){
            String assignee = fields.get(cxProperties.getJiraAssigneeField());
            if(!ScanUtils.empty(assignee)) {
                request.getBugTracker().setAssignee(assignee);
            }
        }

        request.setCxFields(fields);
    }


    /**
     * Process Projects in batch mode - JIRA ONLY
     *
     * @param originalRequest
     */
    public void cxBatch(ScanRequest originalRequest) {
        try {
            List<CxProject> projects;
            List<CompletableFuture<ScanResults>> processes = new ArrayList<>();
            //Get all projects
            if(ScanUtils.empty(originalRequest.getTeam())){
                projects = cxService.getProjects();
            }
            else{ //Get projects for the provided team
                String team = originalRequest.getTeam();
                if(!team.startsWith(cxProperties.getTeamPathSeparator())){
                    team = cxProperties.getTeamPathSeparator().concat(team);
                }
                String teamId = cxService.getTeamId(team);
                projects = cxService.getProjects(teamId);
            }
            for(CxProject project: projects){
                ScanRequest request = new ScanRequest(originalRequest);
                String name = project.getName().replaceAll("[^a-zA-Z0-9-_]+","_");
                //TODO set team when entire instance batch mode
                helperService.getShortUid(request); //update new request object with a unique id for thread log monitoring
                request.setProject(name);
                request.setApplication(name);
                processes.add(cxGetResults(request, project));
            }
            log.info("Waiting for processing to complete");
            processes.forEach(CompletableFuture::join);

        } catch ( CheckmarxException e) {
            log.error(ExceptionUtils.getStackTrace(e));
            log.error("Error occurred while processing projects in batch mode");
            exit(3);
        }
    }

}
