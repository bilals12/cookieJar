# cookieJar

cookieJar is a comprehensive library for handling browser cookies across multiple browsers and operating systems. It includes classes and functions for accessing, decrypting, and managing cookies from browsers like Chrome, Firefox, Opera, Edge, Safari, and others. The code also handles different operating systems and their peculiarities regarding cookie storage and encryption.

The main components of this code are:

Import statements: Necessary libraries are imported, including standard libraries and third-party libraries for handling specific tasks like SQLite3 database operations, encryption and decryption (Cryptodome), and LZ4 compression.

Platform-Specific Handling: The code includes checks for different operating systems (Windows, Linux, macOS, BSD) and adjusts its behavior accordingly.

Browser-Specific Classes: There are classes for each major browser (Chrome, Firefox, Opera, Edge, Safari, etc.) with methods to handle their cookie storage formats and encryption mechanisms.

Utility Functions: Several utility functions are included for tasks like creating local copies of cookie files, expanding file paths based on the operating system, decrypting cookies, and more.

Main Functionalities:

Cookie Loading: The load function combines cookie handling across all supported browsers.
Cookie Decryption: Different decryption methods are implemented for various encryption schemes used by different browsers and operating systems.
Exception Handling: Custom exceptions are defined and used throughout the code to handle specific error scenarios related to browser cookies.

Final Execution Example: The code ends with an example showing how to use the load function to retrieve cookies for a specific domain.