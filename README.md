# Checkmarx-Splunk-Addon
This is a none official Splunk add-on for Checkmarx made by Amit Nakash.
Using Checkmarx REST API this App fetches scan results and write it as new events in Splunk in JSON format.
The Splunk events are automatically parsed, easy to read and understand, and ready to filter using queries.

* Current version - 1.0.0
  
# Installing the Checkmarx TA
To Install the Splunk add-on straight to your Splunk deployment simply follow these few simple steps:

  - Download the file named: 'TA-checkmarx-log-fetcher_1_0_0_export.tgz'.
  - follow this link to the Splunk documentation regarding installing new add-ons in various ways: https://docs.splunk.com/Documentation/AddOns/released/Overview/Installingadd-ons
  - Installing using CLI:
      1. Upload the .tgz file to your Splunk server under location: "/tmp/" ;
         On a distributed SE set-up use your Splunk Manager deployment server for this task.
      2. Unzip the .tgz file to the desited location - "tar xvzf splunk_package_name.tgz -C $SPLUNKHOME/etc/apps";
         For distributed SE use this path - "$SPLUNKHOME/etc/deployment-apps".
      3. For single instance users - 
            * you should now see your new Splunk app ready for use in your Splunk GUI.
      4. For distributed SE - 
            * navigate to your Splunk Manager deployment GUI.
            * Under 'Settings' click 'Forwarder Management'.
            * In the search box type the name of the app - 'TA-checkmarx-log-fetcher'.
            * Click 'Edit'.
            * Using the '+' button assign the app to all of your desired Splunk server classes (make sure to check 'Restart Splunkd').
            * Wait for the Splunk deployments associated with this server class to load back up, you shall now see the app available in the associated deployment's GUI.
                              
# Setting up a new data input:
When clicking on creating a new data input for the app there are several parameters the user needs to fill out.

- Username - This is your Checkmarx user (must have at least 'Read' permission to everything in your CX console).
- Password - Your Checkmarx user's password.
- Client_Id - The client id is a special string representing your user - this is used to generate a bearer token for fetching data.
- Client_Secret - Coupled with your client id, this special string is a super sensitive key that completes the authentication and grants the permission for the app to receive the bearer token.
- Host - Provide your Checkmarx hostname.
- Local path - You should also provide a local path to be used by the app for all relevant needs. e.g. storing a checkpoint file with various values.
- Verify SSL - This checkbox allows you to control wether you would like to include an SSL verification with every HTTP request made by this app. 
- Proxy - In any case you need to use a proxy simply configure your proxy server under 'Configuration' in the data inputs tab inside the app.

# Contact me
Found a bug? want to request a new feature? missing data? API updated?
You can contact me at: amitngithub23@gmail.com
