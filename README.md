# FBLAquiz
FBLAquiz is a web application serving quizzes about everything FBLA!

Demo: https://fblaquiz.live

## Features
### Cross-Platform
Although running FBLAquiz on a modern Linux distro is recommended, it runs on Windows, MacOS, and Linux. The only requirements are Python 3, a WSGI application, and a web server. More details can be found in [INSTALL.md](docs/INSTALL.md).
### Comprehensive Admin Tools
Admins of a site get access to a multitude of tools, including the ability to ban users or remotely reset passwords. Admins also get statistics on problems, such as the solve rate and number of submissions. As well, problems can be created, edited, and deleted at any time. All of these features can be accessed through the web interface. For more advanced admins, interacting with the database using sqlite3 is also possible, but not recommended.
### Fast and Lightweight
Users can get quiz results instantly after they submit. Fast and data-efficient, even on 3G connections. FBLAquiz itself is smaller than 5MB.
### Personalized
Users can get personalized tips to help them perform better. By creating an account, users can save quiz results, get access to detailed statistics, and get personalized training.
### Private and Secure
We take data security very seriously. We do not collect any data about you, the sysadmin, or any users. All data that users send to the site, including passwords and other form data are encrypted with industry-grade encryption. We also do not sell your data, and more information about how we handle user data is available in the Privacy Policy.

## Installation
See [INSTALL.md](docs/INSTALL.md).

## Usage
As an administrator, you will be able to view all submissions, add, edit, and delete questions
through the "Admin Console" interface. As a user, you will be able to take quizzes anonymously as
well as save your attempts in your account and view them at any time.

## License
This project is licensed under the [GNU AGPLv3](LICENSE).
