#include <iostream>     // For input and output operations
#include <fstream>      // For file handling
#include <sstream>      // For string stream operations
#include <Windows.h>    // For Windows-specific functions
#include <Winldap.h>    // For LDAP functions
#include <string>       // For string operations
#include <vector>       // For storing user data
#include <map>          // For clustering errors
#include <algorithm>    // For sorting

using namespace std;

// Link the Wldap32 library for LDAP functions
#pragma comment(lib, "Wldap32.lib")

// Function to print sensitive information safely
void printSensitiveInfo(const string& info)
{
    cout << "Binding with DN: " << info << endl;
}

// Function to add a single LDAP user
int addLDAPUser(LDAP* ldap, const string& id, const string& fullName, const string& phoneNumber, const string& email, const string& department, const string& jobDescription)
{
    int rc = LDAP_SUCCESS;

    // Split the full name into first name and last name
    istringstream iss(fullName);
    string firstName, lastName;
    iss >> firstName;
    getline(iss, lastName);

    // Construct the Distinguished Name (DN) for the new user
    string newUserDN = "cn=" + id + ",ou=users,o=c_plusplus_project";

    // Prepare the attributes for the new user
    LDAPMod mod_cn, mod_sn, mod_givenName, mod_mail, mod_objectClass, mod_department, mod_phoneNumber, mod_jobDescription;
    LDAPMod* mods[9];

    // Set values for each attribute
    char* cn_values[] = { const_cast<char*>(id.c_str()), nullptr };
    char* sn_values[] = { const_cast<char*>(lastName.c_str()), nullptr };
    char* givenName_values[] = { const_cast<char*>(firstName.c_str()), nullptr };
    char* mail_values[] = { const_cast<char*>(email.c_str()), nullptr };
    char* objectClass_values[] = { const_cast<char*>("inetOrgPerson"), const_cast<char*>("organizationalPerson"), const_cast<char*>("person"), const_cast<char*>("top"), nullptr };
    char* department_values[] = { const_cast<char*>(department.c_str()), nullptr };
    char* phoneNumber_values[] = { const_cast<char*>(phoneNumber.c_str()), nullptr };
    char* jobDescription_values[] = { const_cast<char*>(jobDescription.c_str()), nullptr };

    // Fill in LDAPMod structures
    mod_cn.mod_op = LDAP_MOD_ADD;
    mod_cn.mod_type = const_cast<char*>("cn");
    mod_cn.mod_values = cn_values;

    mod_sn.mod_op = LDAP_MOD_ADD;
    mod_sn.mod_type = const_cast<char*>("sn");
    mod_sn.mod_values = sn_values;

    mod_givenName.mod_op = LDAP_MOD_ADD;
    mod_givenName.mod_type = const_cast<char*>("givenName");
    mod_givenName.mod_values = givenName_values;

    mod_mail.mod_op = LDAP_MOD_ADD;
    mod_mail.mod_type = const_cast<char*>("mail");
    mod_mail.mod_values = mail_values;

    mod_objectClass.mod_op = LDAP_MOD_ADD;
    mod_objectClass.mod_type = const_cast<char*>("objectClass");
    mod_objectClass.mod_values = objectClass_values;

    mod_department.mod_op = LDAP_MOD_ADD;
    mod_department.mod_type = const_cast<char*>("ou");
    mod_department.mod_values = department_values;

    mod_phoneNumber.mod_op = LDAP_MOD_ADD;
    mod_phoneNumber.mod_type = const_cast<char*>("telephoneNumber");
    mod_phoneNumber.mod_values = phoneNumber_values;

    mod_jobDescription.mod_op = LDAP_MOD_ADD;
    mod_jobDescription.mod_type = const_cast<char*>("description");
    mod_jobDescription.mod_values = jobDescription_values;

    // Add all attributes to the mods array
    mods[0] = &mod_cn;
    mods[1] = &mod_sn;
    mods[2] = &mod_givenName;
    mods[3] = &mod_mail;
    mods[4] = &mod_objectClass;
    mods[5] = &mod_department;
    mods[6] = &mod_phoneNumber;
    mods[7] = &mod_jobDescription;
    mods[8] = nullptr;

    // Perform the add operation
    rc = ldap_add_ext_sA(ldap, const_cast<char*>(newUserDN.c_str()), mods, nullptr, nullptr);
    return rc;
}

// Function to check if an LDAP user exists
bool userExists(LDAP* ldap, const string& userDN)
{
    int rc = LDAP_SUCCESS;
    LDAPMessage* result = nullptr;

    // Search for the user in the LDAP directory
    rc = ldap_search_ext_sA(ldap, const_cast<char*>(userDN.c_str()), LDAP_SCOPE_BASE, const_cast<char*>("(objectClass=inetOrgPerson)"), nullptr, 0, nullptr, nullptr, nullptr, LDAP_NO_LIMIT, &result);

    if (rc == LDAP_SUCCESS && ldap_count_entries(ldap, result) > 0)
    {
        ldap_msgfree(result);
        return true;
    }

    ldap_msgfree(result);
    return false;
}

// Function to delete all LDAP users under a specific path
int deleteAllLDAPUsers(LDAP* ldap, const string& basePath)
{
    int rc = LDAP_SUCCESS;

    LDAPMessage* result = nullptr;
    LDAPMessage* entry = nullptr;
    string filter = "(objectClass=inetOrgPerson)";
    char* attrs[] = { const_cast<char*>("cn"), nullptr };

    // Construct the search base
    string searchBase = "ou=users," + basePath;

    // Search for all users under the specified base path
    rc = ldap_search_ext_sA(ldap, const_cast<char*>(searchBase.c_str()), LDAP_SCOPE_ONELEVEL, const_cast<char*>(filter.c_str()), attrs, 0, nullptr, nullptr, nullptr, LDAP_NO_LIMIT, &result);

    if (rc != LDAP_SUCCESS)
    {
        cerr << "LDAP search failed: " << ldap_err2stringA(rc) << endl;
        return rc;
    }

    // Check if the user list is empty
    if (ldap_count_entries(ldap, result) == 0)
    {
        cout << "There are no users to delete. Try adding users to the directory first." << endl;
        ldap_msgfree(result);
        return rc;
    }

    // Iterate through the search results and delete each user
    for (entry = ldap_first_entry(ldap, result); entry != nullptr; entry = ldap_next_entry(ldap, entry))
    {
        char* dn = ldap_get_dnA(ldap, entry);
        cout << "Deleting user with DN: " << dn << endl;

        rc = ldap_delete_ext_sA(ldap, dn, nullptr, nullptr);
        if (rc != LDAP_SUCCESS)
        {
            cerr << "Failed to delete user with DN '" << dn << "': " << ldap_err2stringA(rc) << endl;
            ldap_memfreeA(dn);
            continue;
        }

        ldap_memfreeA(dn);
    }

    ldap_msgfree(result);
    cout << "All users have been deleted successfully." << endl;

    return rc;
}

// Function to delete a single LDAP user by user ID
int deleteSingleLDAPUser(LDAP* ldap, const string& userDN)
{
    int rc = LDAP_SUCCESS;

    // Check if the user exists before attempting to delete
    if (!userExists(ldap, userDN))
    {
        cout << "User with DN '" << userDN << "' does not exist." << endl;
        return LDAP_NO_SUCH_OBJECT;
    }

    rc = ldap_delete_ext_sA(ldap, const_cast<char*>(userDN.c_str()), nullptr, nullptr);
    if (rc != LDAP_SUCCESS)
    {
        cerr << "Failed to delete user with DN '" << userDN << "': " << ldap_err2stringA(rc) << endl;
    }
    else
    {
        cout << "User with DN '" << userDN << "' has been deleted successfully." << endl;
    }

    return rc;
}

// Function to check if a line is properly comma-delimited and matches the expected format
bool isProperlyFormatted(const string& line)
{
    istringstream iss(line);
    string token;
    int columnCount = 0;

    while (getline(iss, token, ','))
    {
        columnCount++;
    }

    return columnCount == 6;
}

// Function to display detailed information of a single LDAP user
void displaySingleLDAPUser(LDAP* ldap, const string& userDN)
{
    int rc = LDAP_SUCCESS;

    LDAPMessage* result = nullptr;
    LDAPMessage* entry = nullptr;
    char* attrs[] = { const_cast<char*>("cn"), const_cast<char*>("sn"), const_cast<char*>("givenName"), const_cast<char*>("mail"), const_cast<char*>("ou"), const_cast<char*>("telephoneNumber"), const_cast<char*>("description"), nullptr };

    // Search for the user in the LDAP directory
    rc = ldap_search_ext_sA(ldap, const_cast<char*>(userDN.c_str()), LDAP_SCOPE_BASE, const_cast<char*>("(objectClass=inetOrgPerson)"), attrs, 0, nullptr, nullptr, nullptr, LDAP_NO_LIMIT, &result);

    if (rc != LDAP_SUCCESS)
    {
        cerr << "LDAP search failed: " << ldap_err2stringA(rc) << endl;
        return;
    }

    entry = ldap_first_entry(ldap, result);
    if (entry != nullptr)
    {
        cout << "\nUser Details (DN: " << userDN << "):\n";
        for (int i = 0; attrs[i] != nullptr; i++)
        {
            char* attr = attrs[i];
            BerElement* ber = nullptr;
            char** values = ldap_get_valuesA(ldap, entry, attr);
            if (values)
            {
                cout << attr << ": " << values[0] << endl;
                ldap_value_freeA(values);
            }
        }
    }
    else
    {
        cout << "No user found with DN: " << userDN << endl;
    }

    ldap_msgfree(result);
}

// Function to display all LDAP users under a specific path
void displayAllLDAPUsers(LDAP* ldap, const string& basePath)
{
    int rc = LDAP_SUCCESS;

    LDAPMessage* result = nullptr;
    LDAPMessage* entry = nullptr;
    string filter = "(objectClass=inetOrgPerson)";
    char* attrs[] = { const_cast<char*>("cn"), const_cast<char*>("sn"), const_cast<char*>("givenName"), const_cast<char*>("mail"), const_cast<char*>("ou"), const_cast<char*>("telephoneNumber"), const_cast<char*>("description"), nullptr };

    // Construct the search base
    string searchBase = "ou=users," + basePath;

    // Search for all users under the specified base path
    rc = ldap_search_ext_sA(ldap, const_cast<char*>(searchBase.c_str()), LDAP_SCOPE_ONELEVEL, const_cast<char*>(filter.c_str()), attrs, 0, nullptr, nullptr, nullptr, LDAP_NO_LIMIT, &result);

    if (rc != LDAP_SUCCESS)
    {
        cerr << "LDAP search failed: " << ldap_err2stringA(rc) << endl;
        return;
    }

    // Check if the user list is empty
    if (ldap_count_entries(ldap, result) == 0)
    {
        cout << "There are no users to display. Try adding users to the directory first." << endl;
        ldap_msgfree(result);
        return;
    }

    // Store users in a vector to sort them by ID
    vector<string> users;
    for (entry = ldap_first_entry(ldap, result); entry != nullptr; entry = ldap_next_entry(ldap, entry))
    {
        char* dn = ldap_get_dnA(ldap, entry);
        users.push_back(dn);
        ldap_memfreeA(dn);
    }

    // Sort users by their IDs
    sort(users.begin(), users.end());

    // Display sorted users
    cout << "\nExisting LDAP users under " << searchBase << ":\n";
    for (const auto& user : users)
    {
        cout << "\nUser Details (DN: " << user << "):\n";
        rc = ldap_search_ext_sA(ldap, const_cast<char*>(user.c_str()), LDAP_SCOPE_BASE, const_cast<char*>("(objectClass=inetOrgPerson)"), attrs, 0, nullptr, nullptr, nullptr, LDAP_NO_LIMIT, &result);
        if (rc == LDAP_SUCCESS)
        {
            entry = ldap_first_entry(ldap, result);
            for (int i = 0; attrs[i] != nullptr; i++)
            {
                char* attr = attrs[i];
                BerElement* ber = nullptr;
                char** values = ldap_get_valuesA(ldap, entry, attr);
                if (values)
                {
                    cout << attr << ": " << values[0] << endl;
                    ldap_value_freeA(values);
                }
            }
        }
        ldap_msgfree(result);
    }
}

int main()
{
    // Display application purpose
    cout << "\n\nWelcome to the LDAP User Management Application.\n";
    cout << "This application allows you to manage LDAP users, including adding, viewing, and deleting users.\n";
    cout << "Please follow the prompts to perform the desired operations.\n" << endl;

    LDAP* ldap = nullptr;
    int rc = 0;
    string connectChoice;
    bool firstAttempt = true;

    // LDAP server details
    const char* ldapHost = "xxx.xxx.x.x"; // hidden for security purposes
    int ldapPort = 389;
    const char* ldapUsername = "cn=idamadmin,ou=sa,o=pitg";
    const char* ldapPassword = "xxxxxxxxxxx"; // hidden for security purposes
    string basePath = "o=c_plusplus_project";

    while (true)
    {
        // Prompt user to connect to LDAP server
        if (firstAttempt)
        {
            cout << "Do you want to connect to the LDAP server? (y/n): ";
        }
        else
        {
            cout << "Do you want to connect to the LDAP server again? (y/n): ";
        }
        getline(cin, connectChoice);

        // Convert input to lowercase for case-insensitive comparison
        transform(connectChoice.begin(), connectChoice.end(), connectChoice.begin(), ::tolower);

        if (connectChoice == "y" || connectChoice == "yes")
        {
            firstAttempt = false;
            cout << "Attempting to initialize LDAP connection..." << endl;

            // Initialize LDAP connection
            ldap = ldap_initA(const_cast<char*>(ldapHost), ldapPort);
            if (ldap == nullptr)
            {
                cerr << "Failed to initialize LDAP connection. Please try again later." << endl;
                continue;
            }
            cout << "LDAP connection initialized successfully." << endl;

            cout << "Setting LDAP protocol version..." << endl;

            // Set LDAP options
            ULONG version = LDAP_VERSION3;
            cout << "Setting LDAP option: LDAP_OPT_PROTOCOL_VERSION = " << version << endl;
            rc = ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, reinterpret_cast<void*>(&version));
            if (rc != LDAP_SUCCESS)
            {
                cerr << "Failed to set LDAP protocol version: " << ldap_err2stringA(rc) << endl;
                ldap_unbind_s(ldap);
                continue;
            }
            cout << "LDAP protocol version set successfully." << endl;

            cout << "Attempting LDAP bind..." << endl;

            // Bind to LDAP server (authenticate)
            printSensitiveInfo(ldapUsername);
            rc = ldap_simple_bind_sA(ldap, const_cast<char*>(ldapUsername), const_cast<char*>(ldapPassword));
            if (rc != LDAP_SUCCESS)
            {
                cerr << "LDAP bind failed: " << ldap_err2stringA(rc) << endl;
                ldap_unbind_s(ldap);
                cout << "Please try again later." << endl;
                continue;
            }
            cout << "LDAP bind successful." << endl;

            // Menu-driven interface
            string choice;
            while (true)
            {
                // Display the main menu
                cout << "\n+-------------------------------------+\n";
                cout << "| LDAP User Management Menu           |\n";
                cout << "| Base Path: " << basePath << "     |\n";
                cout << "+-------------------------------------+\n";
                cout << "| 1. Add users from a .csv file       |\n";
                cout << "| 2. View single/all existing users   |\n";
                cout << "| 3. Delete single/all existing users |\n";
                cout << "| 4. Close connection and exit        |\n";
                cout << "+-------------------------------------+\n";
                cout << "Enter your choice: ";
                getline(cin, choice);

                if (choice == "1")
                {
                    // Add users from a .csv file
                    string filePath;

                    while (true)
                    {
                        // Prompt user for the path to the CSV file
                        cout << "Enter the full path to the CSV file (e.g., C:\\path\\to\\file\\company.csv): ";
                        getline(cin, filePath);

                        // Check if the file path is valid
                        if (filePath.empty())
                        {
                            cerr << "Error: The file path is empty. Please enter the correct file again." << endl;
                            continue;
                        }

                        // Check if the file exists
                        ifstream file(filePath);
                        if (!file)
                        {
                            cerr << "Error: The file does not exist. Please enter the correct file again." << endl;
                            continue;
                        }

                        // Check if the file is a CSV file
                        if (filePath.substr(filePath.find_last_of(".") + 1) != "csv")
                        {
                            cerr << "Error: The file is not a CSV file. Please enter the correct file again." << endl;
                            continue;
                        }

                        string line;
                        bool headerChecked = false;
                        bool properFormat = true;
                        bool hasValidDataRow = false;

                        // Structure to store user results
                        struct UserResult
                        {
                            string id;
                            string error;
                        };
                        vector<UserResult> results;
                        vector<string> addedUsers;

                        // Read the CSV file line by line
                        while (getline(file, line))
                        {
                            if (!headerChecked)
                            {
                                // Check if the header is correct
                                if (line != "id,full_name,phone_number,email,department,job_description")
                                {
                                    cerr << "Error: CSV file header is incorrect. Returning to menu." << endl;
                                    properFormat = false;
                                    break;
                                }
                                headerChecked = true;
                                continue;
                            }

                            // Check if the line is properly formatted
                            if (!isProperlyFormatted(line))
                            {
                                cerr << "Error: File is not properly comma-delimited. Returning to menu." << endl;
                                properFormat = false;
                                break;
                            }

                            // Extract user details from the line
                            string id, fullName, phoneNumber, email, department, jobDescription;
                            istringstream iss(line);
                            if (getline(getline(iss, id, ','), fullName, ',') &&
                                getline(getline(getline(getline(iss, phoneNumber, ','), email, ','), department, ','), jobDescription, ','))
                            {
                                string userDN = "cn=" + id + ",ou=users," + basePath;
                                if (userExists(ldap, userDN))
                                {
                                    results.push_back({ id, "User already exists" });
                                }
                                else
                                {
                                    rc = addLDAPUser(ldap, id, fullName, phoneNumber, email, department, jobDescription);
                                    if (rc != LDAP_SUCCESS)
                                    {
                                        results.push_back({ id, ldap_err2stringA(rc) });
                                    }
                                    else
                                    {
                                        hasValidDataRow = true;
                                        addedUsers.push_back(id);
                                    }
                                }
                            }
                        }
                        file.close();

                        // Display results of adding users
                        if (properFormat && !hasValidDataRow)
                        {
                            cerr << "Error: CSV file does not contain any valid data rows. Returning to menu." << endl;
                        }
                        else if (results.empty())
                        {
                            cout << "All users successfully added: ";
                            for (const auto& user : addedUsers)
                            {
                                cout << user << " ";
                            }
                            cout << endl;
                        }
                        else if (addedUsers.empty())
                        {
                            bool sameError = true;
                            string commonError = results[0].error;
                            for (const auto& result : results)
                            {
                                if (result.error != commonError)
                                {
                                    sameError = false;
                                    break;
                                }
                            }
                            if (sameError)
                            {
                                cout << "All users can't be added due to the same reason: " << commonError << endl;
                            }
                            else
                            {
                                map<string, vector<string>> clusteredErrors;
                                for (const auto& result : results)
                                {
                                    clusteredErrors[result.error].push_back(result.id);
                                }
                                cout << "All users can't be added due to the following reasons:" << endl;
                                for (const auto& error : clusteredErrors)
                                {
                                    cout << "Reason: " << error.first << " - Users: ";
                                    for (const auto& id : error.second)
                                    {
                                        cout << id << " ";
                                    }
                                    cout << endl;
                                }
                            }
                        }
                        else
                        {
                            cout << "Some users couldn't be added:" << endl;
                            for (const auto& result : results)
                            {
                                cout << "User ID: " << result.id << " - Reason: " << result.error << endl;
                            }
                            cout << "Successfully added users: ";
                            for (const auto& user : addedUsers)
                            {
                                cout << user << " ";
                            }
                            cout << endl;
                        }

                        break;
                    }
                }
                else if (choice == "2")
                {
                    int userCount = 0;
                    // Check if there are any users to display
                    LDAPMessage* result = nullptr;
                    string filter = "(objectClass=inetOrgPerson)";
                    string searchBase = "ou=users," + basePath;
                    rc = ldap_search_ext_sA(ldap, const_cast<char*>(searchBase.c_str()), LDAP_SCOPE_ONELEVEL, const_cast<char*>(filter.c_str()), nullptr, 0, nullptr, nullptr, nullptr, LDAP_NO_LIMIT, &result);
                    if (rc == LDAP_SUCCESS)
                    {
                        userCount = ldap_count_entries(ldap, result);
                    }
                    ldap_msgfree(result);

                    if (userCount == 0)
                    {
                        cout << "There are no users to view. Try adding users to the directory first." << endl;
                    }
                    else
                    {
                        while (true)
                        {
                            // View single/all existing users
                            string viewChoice;
                            cout << "View a single user or all users? (single/all): ";
                            getline(cin, viewChoice);

                            if (viewChoice == "single")
                            {
                                string userId;
                                cout << "Enter the user ID (cn): ";
                                getline(cin, userId);
                                string userDN = "cn=" + userId + ",ou=users," + basePath;
                                displaySingleLDAPUser(ldap, userDN);
                                break;
                            }
                            else if (viewChoice == "all")
                            {
                                displayAllLDAPUsers(ldap, basePath);
                                break;
                            }
                            else
                            {
                                cout << "Invalid choice. Please enter 'single' or 'all'." << endl;
                            }
                        }
                    }
                }
                else if (choice == "3")
                {
                    int userCount = 0;
                    // Check if there are any users to delete
                    LDAPMessage* result = nullptr;
                    string filter = "(objectClass=inetOrgPerson)";
                    string searchBase = "ou=users," + basePath;
                    rc = ldap_search_ext_sA(ldap, const_cast<char*>(searchBase.c_str()), LDAP_SCOPE_ONELEVEL, const_cast<char*>(filter.c_str()), nullptr, 0, nullptr, nullptr, nullptr, LDAP_NO_LIMIT, &result);
                    if (rc == LDAP_SUCCESS)
                    {
                        userCount = ldap_count_entries(ldap, result);
                    }
                    ldap_msgfree(result);

                    if (userCount == 0)
                    {
                        cout << "There are no users to delete. Try adding users to the directory first." << endl;
                    }
                    else
                    {
                        while (true)
                        {
                            // Delete single/all existing users
                            string deleteChoice;
                            cout << "Delete a single user or all users? (single/all): ";
                            getline(cin, deleteChoice);

                            if (deleteChoice == "single")
                            {
                                string userId;
                                cout << "Enter the user ID (cn): ";
                                getline(cin, userId);
                                string userDN = "cn=" + userId + ",ou=users," + basePath;
                                rc = deleteSingleLDAPUser(ldap, userDN);
                                break;
                            }
                            else if (deleteChoice == "all")
                            {
                                rc = deleteAllLDAPUsers(ldap, basePath);
                                if (rc != LDAP_SUCCESS)
                                {
                                    cerr << "Error deleting LDAP users under base path '" << basePath << "'" << endl;
                                }
                                else
                                {
                                    cout << "Deleted all LDAP users under base path '" << basePath << "'" << endl;
                                }
                                break;
                            }
                            else
                            {
                                cout << "Invalid choice. Please enter 'single' or 'all'." << endl;
                            }
                        }
                    }
                }
                else if (choice == "4")
                {
                    // Exit
                    break;
                }
                else
                {
                    cout << "Invalid choice. Please enter a valid option." << endl;
                }
            }

            // Clean up
            cout << "Unbinding from LDAP server..." << endl;
            ldap_unbind_s(ldap);
            cout << "LDAP unbind successful. Connection closed." << endl;
        }
        else if (connectChoice == "n" || connectChoice == "no")
        {
            cout << "Are you sure you want to exit? (y/n): ";
            string exitChoice;
            getline(cin, exitChoice);
            transform(exitChoice.begin(), exitChoice.end(), exitChoice.begin(), ::tolower);
            if (exitChoice == "y" || exitChoice == "yes")
            {
                cout << "Exiting the program. Goodbye!" << endl;
                break;
            }
            else if (exitChoice == "n" || exitChoice == "no")
            {
                continue;
            }
            else
            {
                cout << "Invalid choice. Please enter 'y' or 'n'." << endl;
            }
        }
        else
        {
            cout << "Invalid choice. Please enter 'y' or 'n'." << endl;
        }
    }

    return 0;
}
