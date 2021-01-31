This file contains information concerning the implementation of `api.go`. In `api.go` you are asked to fill out skeleton code for the functions `RegisterRoutes`, `getProfile`, `updateProfile`. You are also responsible for the implementation of the `Dockerfile` which is in the directory above this one (in `/profiles/` instead of `/profiles/api`). Although you are only changing two files, you should still look at other files as some functions or features may be partially implemented for you.

The table schema for this part of the project is created as follows:

```
CREATE DATABASE profiles;

USE profiles;

CREATE TABLE users (
    firstName VARCHAR(255),
    lastName VARCHAR(255),
    email VARCHAR(255),
    uuid VARCHAR(36) PRIMARY KEY
);

```

You can also find this in `/db-starter/initdb.sql`.

You do not need to fill out the skeleton code in the order below, but it is recommended to do so.

### `RegisterRoutes`

Register the API URL endpoints such that accessing the URL will direct the user to the get profile or the update profile endpoint. Update the router with the relevant HTTP method. You should use the most relevant HTTP method (`GET, POST, PUT, DELETE, PATCH`) for each endpoint.

### `getProfile`

Call the database to retrieve the profile data that corresponds to the UUID in the URL path. Check for any errors and return an internal server error if such an error occurs. Then encode the data as JSON and return it to the client.

We recommend using `mux.Vars` to extract the UUID from the URL. The docs for the `mux.Vars` method can be found here: https://godoc.org/github.com/gorilla/mux#Vars

SQL queries are made against the `users` table, and its schema is mentioned above. The docs for database library can be found here: https://golang.org/pkg/database/sql/

When returning the internal server error, we recommend you use the relevant library methods and constants. The docs for the `http` library can be found here: https://golang.org/pkg/net/http/

### `updateProfile`

Updating profile is similar to `getProfile` but "backwards"; instead of reading data from the database and writing it to the client, you are reading data from the client and writing it to the database.

Firstly, you need to check that the user is updating their own profile. You can do this by extracting the user's UUID from the client cookies and comparing it to the UUID in the API request. Return a status unauthorized error using the `http` library as above.

Then extract the profile data from the API request. You should have done something similar to this when working on `/posts/`. If an error occurs extracting and parsing the profile data, return an internal server error. 

Finally, insert the profile data into our profile database. 

### Dockerfile

Create an image which builds and launches this microservice. You can model this `Dockerfile` after the `Dockerfile` in `/auth-service/`.
