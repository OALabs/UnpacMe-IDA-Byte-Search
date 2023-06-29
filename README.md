# UnpacMe IDA Byte Search
[![UnpacMe](https://img.shields.io/badge/Threat_Hunting-UnpacMe-AA00B4)](https://www.unpac.me/) [![Chat](https://img.shields.io/badge/Support-Discord-5462EB)](https://discord.gg/cw4U3WHvpn)

A search plugin for [UnpacMe](https://unpac.me/) to quickly find related malware samples and determine if a code block is a good
candidate for a detection rule. The plugin searches both malicious files and our goodware corpus.  This allows an analyst to quickly determine
if the block of code belongs to a single known family, multiple families or if it is a common pattern found in goodware.

**The plugin requires a valid API key for [UnpacMe](https://www.unpac.me/).**

## Installation
Before using the plugin you must install the following python modules your IDA environment.

- [requests](https://pypi.org/project/requests/)
- [keyring](https://pypi.org/project/keyring/)

Using pip:
```
pip install requests keyring
```

## Searching

Select the instructions you would like to search for and right click. Then select `UnpacMe Byte Search`.

<p align="center">
    <img width="300" alt="Example Results" src="imgs/search_example.png?raw=true">
</p>

### Search Preview

When the `Search Preview` option is enabled, the plugin will display a preview of the search bytes that can be customized before searching.

<p align="center">
    <img width="600" alt="Example Results" src="imgs/search_preview.png?raw=true">
</p>

### Results

The results window shows a summary of the search results, followed by a table of the raw results. If the pattern is a
good candidate for a rule, you can quickly copy it use the `Copy Pattern` button.  To view the analysis of a file simply
click on the SHA256 hash within the table to open a new browser tab to the analysis on [UnpacMe](https://www.unpac.me).

<p align="center">
    <img width="600" alt="Example Results" src="imgs/example_results.gif?raw=true">
</p>

## Configuration

The plugin has the following configuration options that can be set via the plugin menu.

<p align="center">
    <img width="400" alt="Example Results" src="imgs/config.png?raw=true">
</p>


 - **API Key** - Your Unpac.me API key. This can be found in your account settings on [Unpac.me](https://www.unpac.me/account#/). We use the keyring module
to store the API token within the system keyring.
 - **Log Level** - Set the log verbosity.
 - **Search Preview** - When enabled, the plugin will display a preview of the search bytes that can be edited before searching.
 - **Auto Wildcard** - The plugin will wildcard  `??` bytes likely to change between samples. The following types are wildcarded by
 the plugin when set.
   - Memory References
   - Direct Memory References
   - Memory References with Displacement
   - Immediate Far Address
   - Immediate Near Address
 - **Search Goodware** - When set the plugin will also search the UnpacMe Goodware corpus.


