# Safety and Setup - Automatic Pull Request Task Creation

## Safety
This workflow uses a YAML configuration file to start up an isolated Ubuntu container. The container runs both scripts contained in the "scripts" folder, however, you only need one file in your repository: PR-To-ADO.yaml.

The scripts **cannot** damage your repository. They only **get** information from pull requests. The only code that modifies anything deals with the Azure DevOps API, and even that is run with an access token that can read/write tasks. To be clear: this is a safe workflow.




![img](./img/PR_Automation_Flow_Overview.png)