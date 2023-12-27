# cookieJar

cookieJar is a comprehensive library for handling browser cookies across multiple browsers and operating systems. It includes classes and functions for accessing, decrypting, and managing cookies from browsers like Chrome, Firefox, Opera, Edge, Safari, and others. The code also handles different operating systems and their peculiarities regarding cookie storage and encryption.

1. Import Statements

The program starts by importing necessary libraries. These include standard libraries for file handling, encryption, and database operations, as well as third-party libraries for specialized tasks.

2. Platform-Specific Handling

The code checks the operating system (OS) to determine the correct approach for each platform (Windows, Linux, macOS, BSD). This is crucial because different OSs store browser cookies in different locations and formats.

3. Browser-Specific Classes

The program includes classes for each major browser: Chrome, Firefox, Opera, Edge, Safari. Each class is tailored to handle that browser's specific cookie storage (SQLite for Chrome and Firefox, binary for Safari) and encryption mechanism. For example, Chrome and Opera use similar structures, but Firefox has a different approach.

4. Utility Functions

Copying cookie files: Creates local copies of cookie databases to avoid locking issues.
Path expansion: Adjusts file paths based on the OS and browser profiles.
Decryption: Various functions are implemented to decrypt cookies. Browsers like Chrome or Firefox encrypt stored cookies, and the program must decrypt them to access the actual cookie values.

5. Main Functionalities

Cookie Loading from all browsers: This involves locating the cookie file for each browser, reading the data, and parsing it into a usable format.
Cookie Decryption:
Chrome/Opera/Edge: Uses the AES algorithm. The key is retrieved differently based on the OS: DPAPI on Windows, keychain on macOS, and a combination of hardcoded and OS-specific keys on Linux.
Firefox: Uses a different encryption method, typically involving NSS libraries.
The decryption functions handle these differences, ensuring that the cookies are correctly decrypted regardless of the browser and OS.

6. Exception Handling

The program includes error handling to manage issues specific to browser cookies. This could include file not found errors, access issues, or decryption failures.

7. Final Execution Example

This part of the code demonstrates how to use the load function. The load function is a high-level method that abstracts the complexities of cookie retrieval across different browsers. It allows users to specify a domain, and it returns all relevant cookies for that domain, regardless of the browser they are stored in.
The `load`` function is particularly important as it serves as the interface for the users of this library. It navigates through the browser-specific classes, handles decryption, and aggregates cookies from all available sources, presenting them in a unified format.