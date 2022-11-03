### Terminology
- Tenant - An instance of Azure AD and represents a single organization.
- Azure AD Directory - Each tenant has a dedicated Directory. This is used to perform identity and access management functions for resources. 
- Subscriptions - It is used to pay for services. There can be multiple subscriptions in a Directory.
- Core Domain - The initial domain name <tenant>.onmicrosoft.com is the core domain. it is possible to define custom domain names too.
- Azure resourced are divided into four levels:
  - Management groups
    - Management groups are used to manage multiple subscriptions. 
    - All subscriptions inherit the conditions applied to the management group. 
    - All subscriptions within a single management group belong to the same Azure tenant.
    - A management group can be placed in a lower hierarchy of another management group.
    - There is a single top-level management group - Root management group - for each directory in Azure.
  - Subscriptions
    - An Azure subscription is a logical unit of Azure services that links to an Azure account. 
    - An Azure subscription is a billing and/or access control boundary in an Azure AD Directory. 
    - An Azure AD Directory may have multiple subscriptions but each subscription can only trust a single directory.
    - An Azure role applied at the subscription level applies to all the resources within the subscription.
  - Resource groups
    - A resource group acts as a container for resources. 
    - In Azure, all the resources must be inside a resource group and can belong only to a group. 
    - If a resource group is deleted, all the resources inside it are also deleted. 
    - A resource group has its own Identity and Access Management settings for providing role based access. An Azure role applied to the resource group applied to all the resources in the group.
  - Resources
    - A resource is a deployable item in Azure like VMs, App Services, Storage Accounts etc. 
- Managed identity
  - Azure provides the ability to assign Managed Identities to resources like app service, function apps, virtual machines etc. 
  - Managed Identity uses Azure AD tokens to access other resources (like key vaults, storage accounts) that support Azure AD authentication. 
  - It is a service principal of special type that can be used with Azure resources. 
  - Managed Identity can be system-assigned (tied to a resource and cannot be shared with other resources) or user-assigned (independent life cycle and can be share across resources).
- Azure Resource manager (ARM)
  - It is the client neutral deployment and management service for Azure that is used for lifecycle management (creating, updating and deleting) and access control of of resources.
  - ARM templates can be used for consistent and dependency-defined redeployment of resources.

- Azure RBAC Roles
  - Owner: Full access to all resources and can manage access for other users.
  - Contributor: Full access to all resources, cannot manage access.
  - Reader: View all resources
  - User Access Administrator: View all recources and can manage access for other users.  
- Azure AD roles
  - Global administrator is the most well-known and all powerful administrator role.
  - Global Administrator has the ability to 'elevate' to User Access Administrator Azure role to the root management group.
- Default User Permissions, A normal user has many interesting permissions in Azure AD!
  -   Read all users, Groups, Applications, Devices, Roles, Subscriptions, and their public properties
  -   Invite Guests
  -   Create Security groups
  -   Read non-hidden Group memberships
  -   Add guests to Owned groups
  -   Create new application
  -   Add up to 50 devices to Azure
- Tokens
  - OAuth 2.0 and OIDC use bearer tokens which are JSON Web Tokens. 
  - A bearer token, as the name suggests, grants the bearer access to a protected resource.
  - There are three types of tokens used in OIDC:
    - Access Tokens - The client presents this token to the resource server to access resources. It can be used only for a specific combination of user, client, and resource and cannot be revoked until expiry - that is 1 hour by default. 
    - ID Tokens - The client receives this token from the authorization server. It contains basic information about the user. It is bound to a specific combination of user and client.
    - Refresh Tokens - Provided to the client with access token. Used to get new access and ID tokens. It is bound to a specific combination of user and client and can be revoked. Default expiry is 90 days for inactive refresh tokens and no expiry for active tokens.

  
  
  ### AAD ROLE
  
  - Global Administrator - AAD role -> need to switch to User Adminstration for Azure RM 
  - Application Authenticator => reset password of others
  - Contributor  (Azure RM) -> modify the resource but not prermission 
  - Intune Administrator => execute runBook @ system priv)  (Powershell script, program) against AADJ devices
  - VM adminstrator -> execute VM command (run system privilege)
  
  - Managed Identity - AAD object
  - Application - AAD object
  - Service Principal - AAD object
 
  
 
 - Managed Identiy -> equivalent to AWS instance Profile /Lambda - exeuction roles -> retrive IMDS 169.254.169.254  
 - VM - Managed Identity-> Abuse UserData -> upload 

  ## AdminstrationUnit
  - An administrative unit is an Azure AD resource that can be a container for other Azure AD resources. An administrative unit can contain only users, groups, or devices. Administrative units restrict permissions in a role to any portion of your organization that you define. 
  
  Deployment scenario
It can be useful to restrict administrative scope by using administrative units in organizations that are made up of independent divisions of any kind. Consider the example of a large university that's made up of many autonomous schools (School of Business, School of Engineering, and so on). Each school has a team of IT admins who control access, manage users, and set policies for their school.

  ![image](https://user-images.githubusercontent.com/18033272/199667717-eae403b3-6aad-45ec-8841-7889846c8c89.png)

A central administrator could:

Create an administrative unit for the School of Business.
Populate the administrative unit with only students and staff within the School of Business.
Create a role with administrative permissions over only Azure AD users in the School of Business administrative unit.
Add the business school IT team to the role, along with its scope.
Screenshot of Devices and Administrative units page with Remove from administrative unit option.

Constraints
Here are some of the constraints for administrative units.

Administrative units can't be nested.
Administrative unit-scoped user account administrators can't create or delete users.
Administrative units are currently not available in Azure AD Identity Governance.
Groups
Adding a group to an administrative unit brings the group itself into the management scope of the administrative unit, but not the members of the group. In other words, an administrator scoped to the administrative unit can manage properties of the group, such as group name or membership, but they cannot manage properties of the users or devices within that group (unless those users and devices are separately added as members of the administrative unit).

For example, a User Administrator scoped to an administrative unit that contains a group can and can't do the following:

Permissions	Can do

  Permissions	Can do
- Manage the name of the group	✔️
- Manage the membership of the group	✔️
- Manage the user properties for individual members of the group	❌
- Manage the user authentication methods of individual members of the group	❌
- Reset the passwords of individual members of the group	❌

