﻿# LightJson

A minimalist JSON library designed to easily encode and decode JSON messages.

[![Build and Tests](https://github.com/MarcosLopezC/LightJson/actions/workflows/build-and-tests.yml/badge.svg)](https://github.com/MarcosLopezC/LightJson/actions/workflows/build-and-tests.yml)

## Features

     - Strict adherence to JSON Standard as defined in [json.org](http://json.org/).
                                                           - Expressive fluent API.
                                                       - Configurable output (minified/pretty).
 - Enhanced debugging data for Visual Studio.

# Usage

## Creating a JSON message

    ```C#
var json = new JsonObject
    {
        ["menu"] = new JsonArray
        {
            "home",
            "projects",
            "about",
        }
    }.ToString(pretty: true);
    ```

JSON output:

    ```JSON
{
    "menu": [
    "home",
    "projects",
    "about"
        ]
}
```

## Reading a JSON message

In this example, the variable `json` contains the string generated in the previous example.

    ```C#
var menu = JsonValue.Parse(json)["menu"].AsJsonArray;

foreach (var item in menu)
{
    Console.WriteLine(item);
}
```

Console output:

    ```
home
    projects
about
    ```

# License

MIT License ([Read License](LICENSE.txt)).

# Author

- Marcos López C. (MarcosLopezC) <MarcosLopezC@live.com>

## Contributors

    - Trevor Stavropoulos (tstavropoulos) <Trevor.Stavropoulos@gmail.com>
    - Sam Harwell (sharwell)
    - saiedkia
    - Björn Hellander (bjornhellander)
    - Vitor Rodrigues (vsilvar)