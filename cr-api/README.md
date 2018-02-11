Welcome to the Crunch.io api fitness test.

Here you will find a python package to help us evaluate your skills with:

1. Problem Solving
2. Web Server API Design
3. Request-time data manipulation
4. Testing strategies

Instructions

1. Fork the repo into a private repo.
2. Create a virtualenv for this project and install the cr-api and cr-db packages into your environment.
3. Modify the cr-api package to complete the task, the code is commented with task items.
4. Let us know when you have finished.

Deliverable

Publish your work in a GitHub repository.  Please use Python 2.x for your coding.  Feel free to modify this 
readme to give any additional information a reviewer might need.

Implementation Details

Adeel adeelyounas@gmail.com

Assumptions

- Support API and Browser/Session login as it was not clear if API should be browsable.
    Added token collection where tokens can be persisted for API.
- When login in browser session is created, and user can see menu options.
- When login via API, user gets token back, that can be used (as "Authorization" header) to
    make further requests where authentication is required.
- When running application in debug mode (`python cr/api/server.py`) default user with email `admin@fit.com`
    and password `pass` is create, which can be used to login perform further actions.
- Testing can be done on API endpoint, there are few tests which just check for authentication at the moment and be further improved.
