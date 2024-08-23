/*
 * SPDX-FileCopyrightText: Copyright (c) 2023-2024 NVIDIA CORPORATION &
 * AFFILIATES. All rights reserved. SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cper.h>

using namespace std;
using json = nlohmann::ordered_json;
#define PHASE1
string convertToHex(unsigned char* input, int size);

/* Modifying code to deploy Phase 1*/

// output object to write into the JSON file
json j;

/* ************ HELPER FUNCTIONS ************ */

/**
 * Signature End Validation
 *
 * This function validates if the Signature End which is a field as part of the
 * header has its value as 0xFFFFFFFF
 *
 *
 * @param input Pointer to the 4 bytes of signature end
 * @return TRUE if signature end is valid, FALSE otherwise
 */

bool SignatureEndValidation(unsigned char* input)
{
    for (int i = 0; i < 4; i++)
    {
        if (!((int)input[i] == signatureEndMarker))
        {
            return false;
        }
    }
    return true;
}

/**
 * Convert to String
 *
 * This function takes a char array and its size as the input and returns a
 * string as its output
 *
 * @param input the input char array @param size Defines the size of the array
 * passed
 * @return temp which is the string output
 */
string convertToString(unsigned char* input, int size)
{
    string temp(input, input + size);
    return temp;
}

/**
 * Convert to ASCII formatted string
 *
 * This function takes a char array and its size as the input and returns a
 * string in its ASCII format as its output
 *
 * @param input the input char array @param size Defines the size of the array
 * passed
 * @return temp which is the string output
 */
string convertToStringAscii(unsigned char input[], int size)
{
    int i;
    for (i = 0; i < size; i++)
    {
        if ((int)input[i] == 0)
            break;
    }
    string temp(input, input + i);
    return temp;
}

/**
 * Convert from a string to integer
 *
 * This function takes a string as its input and returns an
 * integer as its output
 *
 * @param input in the form of a string
 * @return corresponding integer value
 */
int stringToInt(string input)
{
    int result = 0;
    for (int i = 0; i < (int)input.size(); i++)
    {
        result += (int)input[i];
        result *= 10;
    }
    return (int)result / 10;
}

/**
 * Reformatting the Timestamp field
 *
 * This function takes a pointer to the timestamp array and formats it into a
 * string of a specific format NOTE: To be changed based on Redfish format
 * @param temp input to the function which is a pointer to the timestamp char
 * array
 * @return result which is the formatted string
 */
string timestampDecode(unsigned char* temp)
{
    string time = convertToHex(temp, sizeof(temp));
    string result = "Format: MM-DD-YYYY HH:MM:SS ";

    // Extract year, month, and day from the timestamp string
    string year1 = time.substr(14, 2);
    string year2 = time.substr(12, 2);
    string month = time.substr(10, 2);
    string day = time.substr(8, 2);

    // Extract hour, minute, and second from the timestamp string
    string second = time.substr(0, 2);
    string minute = time.substr(2, 2);
    string hour = time.substr(4, 2);

    // Construct the formatted timestamp string
    result += month + "-" + day + "-" + year1 + year2 + " " + hour + ":" +
              minute + ":" + second;

    return result;
}

/**
 * Convert to HEX formatted string
 *
 * This function takes a char array and its size as the input and returns a
 * string in its HEX format as its output
 *
 * @param input the input char array @param size Defines the size of the array
 * passed
 * @return result which is the string output
 */
string convertToHex(unsigned char* input, int size)
{
    stringstream result;
    for (int k = 0; k < size; k++)
    {
        result << hex << std::setfill('0') << std::setw(2) << (int)input[k];
    }
    return result.str();
}

/**
 * Convert to HEX formatted string from an input of a char array in little
 * endian
 *
 * This function takes a char array and its size as the input and returns a
 * string in its HEX format as its output considering the input to be in little
 * endian
 *
 * @param input the input char array @param size Defines the size of the array
 * passed
 * @return result which is the string output
 */
string convertToHexLittleEndian(unsigned char* input, int size)
{
    stringstream result;
    for (int k = size - 1; k > -1; k--)
    {
        result << hex << std::setfill('0') << std::setw(2) << (int)input[k];
    }
    return result.str();
}

/**
 * Convert to integer from a char array stored in little endian
 *
 * This function takes a char array and its size as the input and returns an
 * integer as its output considering the input to be in little endian
 *
 * @param input the input char array @param size Defines the size of the array
 * passed
 * @return result which is the integer output
 */
long int charToIntLittleEndian(unsigned char* input, int size)
{
    long int result = 0;
    for (int i = size - 1; i >= 0; i--)
    {
        if (input[i] == 0x0A)
        {
            result += 10;
        }
        else
            result += input[i];
        result = result << 8;
    }
    return (result >> 8);
}

/**
 * Reformatting the GUID field
 *
 * This function takes a string as its input and reformats it to a standard GUID
 * representation
 *
 * @param input to the function which is a string
 * @return result which is the formatted string
 */
string guidDecode(string input)
{
    string result;
    for (int i = 6; i >= 0; i = i - 2)
    {
        result = result + input[i] + input[i + 1];
    }
    result = result + '-';
    for (int i = 10; i >= 8; i = i - 2)
    {
        result = result + input[i] + input[i + 1];
    }
    result = result + '-';
    for (int i = 14; i >= 12; i = i - 2)
    {
        result = result + input[i] + input[i + 1];
    }
    result = result + '-';
    for (int i = 16; i <= 19; i = i + 1)
    {
        result = result + input[i];
    }
    result = result + '-';
    for (int i = 20; i < 32; i++)
    {
        result = result + input[i];
    }
    return result;
}

// Defining hashmaps for certain fields with multiple possibilities
map<int, string> errorSev;
map<int, string> headerFlags;
map<int, string> sectionSeverity;
map<int, string> memErrType;

/**
 * Initialize hashmaps
 *
 * This function initializes the defined hashmaps
 *
 * @param none
 * @return void
 */
void initMaps()
{
    errorSev[0] = "Recoverable";
    errorSev[1] = "Fatal";
    errorSev[2] = "Corrected";
    errorSev[3] = "Informational";
    headerFlags[1] = "HW_ERROR_FLAGS_RECOVERED";
    headerFlags[2] = "HW_ERROR_FLAGS_PREVERR";
    headerFlags[4] = "HW_ERROR_FLAGS_SIMULATED";
    sectionSeverity[0] = "Correctable";
    sectionSeverity[1] = "Fatal";
    sectionSeverity[2] = "Corrected";
    sectionSeverity[3] = "None";
    memErrType[0] = "Unknown";
    memErrType[1] = "No Error";
    memErrType[2] = "Sngle-bit ECC";
    memErrType[3] = "Multi-bit ECC";
    memErrType[4] = "Single-symbol ChipKill ECC";
    memErrType[5] = "Multi-symbol ChipKill ECC";
    memErrType[6] = "Master abort";
    memErrType[7] = "Target abort";
    memErrType[8] = "Parity Error";
    memErrType[9] = "Watchdog timeout";
    memErrType[10] = "Invalid address";
    memErrType[11] = "Mirror Broken";
    memErrType[12] = "Memory Sparing";
    memErrType[13] = "Scrub corrected error";
    memErrType[14] = "Scrub uncorrected error";
    memErrType[15] = "Physical Memory Map-out event";
}

/**
 * Function to check for validation bits in memory error section
 *
 * This function checks for different bits to be set and appropriately assigns a
 * valid or invalid result
 *
 * @param input is the pointer to the bytes of information to be used and i is
 * the section iterator
 * @return void
 */
void memErrValidationBitsDecode(unsigned char* input, int i)
{
    for (int k = 0; k < 8; k++)
    {
        switch (k)
        {
            case 0:
                j["Sections"][i]["Section"]["ValidationBits"]
                 ["ErrorStatusValidity"] =
                     (((int)input[7] & (0x01 << k)) == (0x01 << k)) ? "Valid"
                                                                    : "Invalid";
                break;
            case 1:
                j["Sections"][i]["Section"]["ValidationBits"]
                 ["PhysicalAddressValidity"] =
                     (((int)input[7] & (0x01 << k)) == (0x01 << k)) ? "Valid"
                                                                    : "Invalid";
                break;
            case 2:
                j["Sections"][i]["Section"]["ValidationBits"]
                 ["PhysicalAddressMaskValidity"] =
                     (((int)input[7] & (0x01 << k)) == (0x01 << k)) ? "Valid"
                                                                    : "Invalid";
                break;
            case 3:
                j["Sections"][i]["Section"]["ValidationBits"]["NodeValidity"] =
                    (((int)input[7] & (0x01 << k)) == (0x01 << k)) ? "Valid"
                                                                   : "Invalid";
                break;
            case 4:
                j["Sections"][i]["Section"]["ValidationBits"]["CardValidity"] =
                    (((int)input[7] & (0x01 << k)) == (0x01 << k)) ? "Valid"
                                                                   : "Invalid";
                break;
            case 5:
                j["Sections"][i]["Section"]["ValidationBits"]
                 ["ModuleValidity"] =
                     (((int)input[7] & (0x01 << k)) == (0x01 << k)) ? "Valid"
                                                                    : "Invalid";
                break;
            case 6:
                j["Sections"][i]["Section"]["ValidationBits"]["BankValidity"] =
                    (((int)input[7] & (0x01 << k)) == (0x01 << k)) ? "Valid"
                                                                   : "Invalid";
                break;
            case 7:
                j["Sections"][i]["Section"]["ValidationBits"]
                 ["DeviceValidity"] =
                     (((int)input[7] & (0x01 << k)) == (0x01 << k)) ? "Valid"
                                                                    : "Invalid";
                break;
        }
    }
    for (int k = 0; k < 8; k++)
    {
        switch (k)
        {
            case 0:
                j["Sections"][i]["Section"]["ValidationBits"]["RowValidity"] =
                    (((int)input[6] & (0x01 << k)) == (0x01 << k)) ? "Valid"
                                                                   : "Invalid";
                break;
            case 1:
                j["Sections"][i]["Section"]["ValidationBits"]
                 ["ColumnValidity"] =
                     (((int)input[6] & (0x01 << k)) == (0x01 << k)) ? "Valid"
                                                                    : "Invalid";
                break;
            case 2:
                j["Sections"][i]["Section"]["ValidationBits"]
                 ["BitPositionValidity"] =
                     (((int)input[6] & (0x01 << k)) == (0x01 << k)) ? "Valid"
                                                                    : "Invalid";
                break;
            case 3:
                j["Sections"][i]["Section"]["ValidationBits"]
                 ["PlatformRequestorIDValidity"] =
                     (((int)input[6] & (0x01 << k)) == (0x01 << k)) ? "Valid"
                                                                    : "Invalid";
                break;
            case 4:
                j["Sections"][i]["Section"]["ValidationBits"]
                 ["PlatformResponderIDValidity"] =
                     (((int)input[6] & (0x01 << k)) == (0x01 << k)) ? "Valid"
                                                                    : "Invalid";
                break;
            case 5:
                j["Sections"][i]["Section"]["ValidationBits"]
                 ["MemoryPlatformTargetValidity"] =
                     (((int)input[6] & (0x01 << k)) == (0x01 << k)) ? "Valid"
                                                                    : "Invalid";
                break;
            case 6:
                j["Sections"][i]["Section"]["ValidationBits"]
                 ["MemoryErrorTypeValidity"] =
                     (((int)input[6] & (0x01 << k)) == (0x01 << k)) ? "Valid"
                                                                    : "Invalid";
                break;
            case 7:
                j["Sections"][i]["Section"]["ValidationBits"]
                 ["RankNumberValidity"] =
                     (((int)input[6] & (0x01 << k)) == (0x01 << k)) ? "Valid"
                                                                    : "Invalid";
                break;
        }
    }
    for (int k = 0; k < 6; k++)
    {
        switch (k)
        {
            case 0:
                j["Sections"][i]["Section"]["ValidationBits"]
                 ["CardHandleValidity"] =
                     (((int)input[5] & (0x01 << k)) == (0x01 << k)) ? "Valid"
                                                                    : "Invalid";
                break;
            case 1:
                j["Sections"][i]["Section"]["ValidationBits"]
                 ["ModuleHandleValidity"] =
                     (((int)input[5] & (0x01 << k)) == (0x01 << k)) ? "Valid"
                                                                    : "Invalid";
                break;
            case 2:
                j["Sections"][i]["Section"]["ValidationBits"]
                 ["ExtendedRowValidity"] =
                     (((int)input[5] & (0x01 << k)) == (0x01 << k)) ? "Valid"
                                                                    : "Invalid";
                break;
            case 3:
                j["Sections"][i]["Section"]["ValidationBits"]
                 ["BankGroupValidity"] =
                     (((int)input[5] & (0x01 << k)) == (0x01 << k)) ? "Valid"
                                                                    : "Invalid";
                break;
            case 4:
                j["Sections"][i]["Section"]["ValidationBits"]
                 ["BankAddressValidity"] =
                     (((int)input[5] & (0x01 << k)) == (0x01 << k)) ? "Valid"
                                                                    : "Invalid";
                break;
            case 5:
                j["Sections"][i]["Section"]["ValidationBits"]
                 ["ChipIdentificationValidity"] =
                     (((int)input[5] & (0x01 << k)) == (0x01 << k)) ? "Valid"
                                                                    : "Invalid";
                break;
        }
    }
}

/**
 * Function to check for validation bits in PCI Express error section
 *
 * This function checks for different bits to be set and appropriately assigns a
 * valid or invalid result
 *
 * @param input is the pointer to the bytes of information to be used and i is
 * the section iterator
 * @return void
 */
void pcieErrValidationBitsDecode(unsigned char* input, int i)
{
    for (int k = 0; k < 8; k++)
    {
        switch (k)
        {
            case 0:
                j["Sections"][i]["Section"]["ValidationBits"]
                 ["PortTypeValidity"] =
                     (((int)input[7] & (0x01 << k)) == (0x01 << k)) ? "Valid"
                                                                    : "Invalid";
                break;
            case 1:
                j["Sections"][i]["Section"]["ValidationBits"]
                 ["VersionValidity"] =
                     (((int)input[7] & (0x01 << k)) == (0x01 << k)) ? "Valid"
                                                                    : "Invalid";
                break;
            case 2:
                j["Sections"][i]["Section"]["ValidationBits"]
                 ["CommandStatusValidity"] =
                     (((int)input[7] & (0x01 << k)) == (0x01 << k)) ? "Valid"
                                                                    : "Invalid";
                break;
            case 3:
                j["Sections"][i]["Section"]["ValidationBits"]
                 ["DeviceIDValidity"] =
                     (((int)input[7] & (0x01 << k)) == (0x01 << k)) ? "Valid"
                                                                    : "Invalid";
                break;
            case 4:
                j["Sections"][i]["Section"]["ValidationBits"]
                 ["DeviceSerialNumberValidity"] =
                     (((int)input[7] & (0x01 << k)) == (0x01 << k)) ? "Valid"
                                                                    : "Invalid";
                break;
            case 5:
                j["Sections"][i]["Section"]["ValidationBits"]
                 ["BridgeControlStatusValidity"] =
                     (((int)input[7] & (0x01 << k)) == (0x01 << k)) ? "Valid"
                                                                    : "Invalid";
                break;
            case 6:
                j["Sections"][i]["Section"]["ValidationBits"]
                 ["CapabilityStructureStatusValidity"] =
                     (((int)input[7] & (0x01 << k)) == (0x01 << k)) ? "Valid"
                                                                    : "Invalid";
                break;
            case 7:
                j["Sections"][i]["Section"]["ValidationBits"]
                 ["AERInfoValidity"] =
                     (((int)input[7] & (0x01 << k)) == (0x01 << k)) ? "Valid"
                                                                    : "Invalid";
                break;
        }
    }
}

/**
 * Function to check for validation bits in ARM Processor error section
 *
 * This function checks for different bits to be set and appropriately assigns a
 * valid or invalid result
 *
 * @param input is the pointer to the bytes of information to be used and i is
 * the section iterator
 * @return void
 */
void armErrValidationBitsDecode(unsigned char* input, int i)
{
    for (int k = 0; k < 4; k++)
    {
        switch (k)
        {
            case 0:
                j["Sections"][i]["Section"]["ValidationBits"]["MPIDRValidity"] =
                    (((int)input[7] & (0x01 << k)) == (0x01 << k)) ? "Valid"
                                                                   : "Invalid";
                break;
            case 1:
                j["Sections"][i]["Section"]["ValidationBits"]
                 ["ErrorAffinityLevelValidity"] =
                     (((int)input[7] & (0x01 << k)) == (0x01 << k)) ? "Valid"
                                                                    : "Invalid";
                break;
            case 2:
                j["Sections"][i]["Section"]["ValidationBits"]
                 ["RunningStateValidity"] =
                     (((int)input[7] & (0x01 << k)) == (0x01 << k)) ? "Valid"
                                                                    : "Invalid";
                break;
            case 3:
                j["Sections"][i]["Section"]["ValidationBits"]
                 ["VendorSpecificInfoValidity"] =
                     (((int)input[7] & (0x01 << k)) == (0x01 << k)) ? "Valid"
                                                                    : "Invalid";
                break;
        }
    }
}

/**
 * Function to check for a particular Error Status Type (Memory Error Section)
 *
 * This function checks for different values of the error status type and
 * defines the type of errors for the same
 *
 * @param input is the value of the byte in the log file corresponding to error
 * type and i is the section iterator
 * @return void
 */
void memErrErrorStatusTypeDecode(int input, int i)
{
    switch (input)
    {
        case 1:
            j["Sections"][i]["Section"]["ErrorStatus"]["ErrorType"] =
                "ERR_INTERNAL";
            break;
        case 16:
            j["Sections"][i]["Section"]["ErrorStatus"]["ErrorType"] = "ERR_BUS";
            break;
        case 4:
            j["Sections"][i]["Section"]["ErrorStatus"]["ErrorType"] = "ERR_MEM";
            break;
        case 5:
            j["Sections"][i]["Section"]["ErrorStatus"]["ErrorType"] = "ERR_TLB";
            break;
        case 6:
            j["Sections"][i]["Section"]["ErrorStatus"]["ErrorType"] =
                "ERR_CACHE";
            break;
        case 7:
            j["Sections"][i]["Section"]["ErrorStatus"]["ErrorType"] =
                "ERR_FUNCTION";
            break;
        case 8:
            j["Sections"][i]["Section"]["ErrorStatus"]["ErrorType"] =
                "ERR_SELFTEST";
            break;
        case 9:
            j["Sections"][i]["Section"]["ErrorStatus"]["ErrorType"] =
                "ERR_FLOW";
            break;
        case 17:
            j["Sections"][i]["Section"]["ErrorStatus"]["ErrorType"] = "ERR_MAP";
            break;
        case 18:
            j["Sections"][i]["Section"]["ErrorStatus"]["ErrorType"] =
                "ERR_IMPROPER";
            break;
        case 19:
            j["Sections"][i]["Section"]["ErrorStatus"]["ErrorType"] =
                "ERR_UNIMPL";
            break;
        case 20:
            j["Sections"][i]["Section"]["ErrorStatus"]["ErrorType"] = "ERR_LOL";
            break;
        case 21:
            j["Sections"][i]["Section"]["ErrorStatus"]["ErrorType"] =
                "ERR_RESPONSE";
            break;
        case 22:
            j["Sections"][i]["Section"]["ErrorStatus"]["ErrorType"] =
                "ERR_PARITY";
            break;
        case 23:
            j["Sections"][i]["Section"]["ErrorStatus"]["ErrorType"] =
                "ERR_PROTOCOL";
            break;
        case 24:
            j["Sections"][i]["Section"]["ErrorStatus"]["ErrorType"] =
                "ERR_ERROR";
            break;
        case 25:
            j["Sections"][i]["Section"]["ErrorStatus"]["ErrorType"] =
                "ERR_TIMEOUT";
            break;
        case 26:
            j["Sections"][i]["Section"]["ErrorStatus"]["ErrorType"] =
                "ERR_POISONED";
            break;
        default:
            j["Sections"][i]["Section"]["ErrorStatus"]["ErrorType"] =
                "Reserved";
            break;
    }
}

/**
 * Function to check for a particular Port Type (PCI Express Error Section)
 *
 * This function checks for different values of the port type and defines the
 * type of port for the same
 *
 * @param input is the value of the byte in the log file corresponding to port
 * type and i is the section iterator
 * @return void
 */
void pcieErrPortTypeDecode(int input, int i)
{
    switch (input)
    {
        case 0:
            j["Sections"][i]["Section"]["PortType"] = "PCI Express End Point";
            break;
        case 1:
            j["Sections"][i]["Section"]["PortType"] =
                "Legacy PCI End Point Device";
            break;
        case 4:
            j["Sections"][i]["Section"]["PortType"] = "Root Port";
            break;
        case 5:
            j["Sections"][i]["Section"]["PortType"] = "Upstream Switch Port";
            break;
        case 6:
            j["Sections"][i]["Section"]["PortType"] = "Downstream Switch Port";
            break;
        case 7:
            j["Sections"][i]["Section"]["PortType"] =
                "PCI Express to PCI/PCI-X Bridge";
            break;
        case 8:
            j["Sections"][i]["Section"]["PortType"] =
                "PCI/PCI-X to PCI Express Bridge";
            break;
        case 9:
            j["Sections"][i]["Section"]["PortType"] =
                "Root Complex Integrated Endpoint Device";
            break;
        case 10:
            j["Sections"][i]["Section"]["PortType"] =
                "Root Complex Event Collector";
            break;
        default:
            j["Sections"][i]["Section"]["PortType"] = "No port type defined";
            break;
    }
}
/**
 * Helper function to append 0x to a string
 *
 * This function appends a 0x in order to represent a string as an address in
 * the hex notation
 *
 * @param input is the string which consisting of an address
 * @return string
 */
string addressRepresentation(string input)
{
    string x("0x");
    x.append(input);
    return x;
}

int main(int argc, char** argv)
{
    // initialize hash maps
    initMaps();
    CLI::App app{"CPER Decoder"}; // label the command line interface
    string inputFile;
    app.add_option(
        "--redfish", inputFile,
        "Binary File Path"); // provide an input option for the binary blob path
    string outputFile;
    app.add_option(
        "--json", outputFile,
        "JSON File Path"); // provide an output option for the JSON file
    CLI11_PARSE(app, argc, argv);
    ifstream binFile;
    ofstream jsonFile;
    string line;
    binFile.open(inputFile, ios::in | ios::binary); // open file in read mode
    ostringstream ostrm;
    ostrm << binFile.rdbuf();      // read the entire input binary file into an
                                   // output stringstream
    line = ostrm.str();            // convert from type ostringstream to string

    header* p = (header*)&line[0]; // read the file into the header structure to
                                   // be able to segregate fields

    jsonFile.open(outputFile);

    // Write the header fields into the JSON file
    string revision = convertToString(p->Revision, sizeof(p->Revision));
    string sectionCount = convertToString(p->SectionCount,
                                          sizeof(p->SectionCount));
#ifndef PHASE1
    j["Header"]["SignatureStart"] = convertToString(p->signatureStart,
                                                    sizeof(p->signatureStart));
    j["Header"]["MajorRevision"] = revision[1];
    j["Header"]["MinorRevision"] = revision[0];
    j["Header"]["SignatureEnd"] =
        SignatureEndValidation(p->SignatureEnd) ? "Valid" : "Invalid";
#endif
    reverse(sectionCount.begin(), sectionCount.end());
    int secCount = stringToInt(sectionCount);

    j["Header"]["SectionCount"] = secCount;
#ifndef PHASE1
    if (errorSev.find((int)p->ErrorSeverity[0]) != errorSev.end())
    {
        j["Header"]["ErrorSeverity"] = errorSev[p->ErrorSeverity[0]];
    }
    j["Header"]["PlatformIDValidation"] =
        ((int)p->ValidationBits[0] & 0x1) == 0x01 ? "Valid" : "Invalid";
    j["Header"]["TimestampValidation"] =
        ((int)p->ValidationBits[0] & 0x2) == 0x02 ? "Valid" : "Invalid";
    j["Header"]["PartitionIDValidation"] =
        ((int)p->ValidationBits[0] & 0x4) == 0x04 ? "Valid" : "Invalid";
    j["Header"]["RecordLength"] =
        charToIntLittleEndian(p->RecordLength, sizeof(p->RecordLength));
    string time = convertToHex(p->Timestamp, sizeof(p->Timestamp));
    j["Header"]["Timestamp"] = timestampDecode(p->Timestamp);
    j["Header"]["PlatformID"] =
        guidDecode(convertToHex(p->PlatformID, sizeof(p->PlatformID)));
    j["Header"]["PartitionID"] =
        guidDecode(convertToHex(p->PartitionID, sizeof(p->PartitionID)));
    j["Header"]["CreatorID"] =
        guidDecode(convertToHex(p->CreatorID, sizeof(p->CreatorID)));
#endif
    j["Header"]["NotificationType"] = guidDecode(
        convertToHex(p->NotificationType, sizeof(p->NotificationType)));
#ifndef PHASE1
    j["Header"]["RecordID"] = convertToHex(p->RecordID, sizeof(p->RecordID));
    if (headerFlags.find((int)p->Flags[0]) != headerFlags.end())
    {
        j["Header"]["Flags"] = headerFlags[p->Flags[0]];
    }
    else
    {
        j["Header"]["Flags"] = "No Flags set";
    }
    j["Header"]["PersistenceInformation"] =
        "Field defined by the creator. Out of scope of this specification";
#endif
    // Writing the Section Descriptors into the JSON file
    const char* temp = line.c_str();
    vector<sectionDescriptor> sections(secCount);
    vector<int> secOffset(secCount);
    vector<int> secLength(secCount);
    vector<int> secTrack(secCount);
    vector<string> secTrackString(secCount);
    for (int i = 0; i < secCount; i++)
    {
        memcpy(&sections[i], temp + sbmrOffset + headerSize + (secDescSize * i),
               72);
    }
    for (int i = 0; i < secCount; i++)
    {
        secOffset[i] = charToIntLittleEndian(sections[i].sectionOffset,
                                             sizeof(sections[i].sectionOffset));
        secLength[i] = charToIntLittleEndian(sections[i].sectionLength,
                                             sizeof(sections[i].sectionLength));
        (void)secLength[i];
#ifndef PHASE1
        j["Sections"][i]["SectionDescriptor"]["SectionOffset"] = secOffset[i];
        j["Sections"][i]["SectionDescriptor"]["SectionLength"] = secLength[i];
        string rev = (convertToString(sections[i].revision,
                                      sizeof(sections[i].revision)));
        j["Sections"][i]["SectionDescriptor"]["MajorRevision"] = rev[1];
        j["Sections"][i]["SectionDescriptor"]["MinorRevision"] = rev[0];
        j["Sections"][i]["SectionDescriptor"]["FRUIdValidity"] =
            ((((int)sections[i].validationBits[0]) & 0x01) == 0x01)
                ? "FRUId Valid"
                : "FRUId Invalid";
        j["Sections"][i]["SectionDescriptor"]["FRUStringValidity"] =
            ((((int)sections[i].validationBits[0]) & 0x02) == 0x02)
                ? "FRUString Valid"
                : "FRUString Invalid";

        string flagErrors[8] = {"Primary Error",
                                "Containment Warning",
                                "Reset",
                                "Error threshold exceeded",
                                "Resource not accessible",
                                "Latent Error",
                                "Propogated",
                                "Overflow"};
        int count = 0;
        for (int k = 0; k < 8; k++)
        {
            if (((int)sections[i].flags[0] & (0x01 << k)) == (0x01 << k))
            {
                j["Sections"][i]["SectionDescriptor"]["Flags"][count] =
                    flagErrors[k];
                count = count + 1;
            }
        }
        if (count == 0)
        {
            j["Sections"][i]["SectionDescriptor"]["Flags"][count] =
                "No Flags Set";
        }
#endif
        string temp = convertToHex(sections[i].sectionType,
                                   sizeof(sections[i].sectionType));
        if (temp.compare(nvda) == 0)
        {
            secTrack[i] = 1;
            secTrackString[i] = "NVIDIA CPER Error Section";
        }
        else if (temp.compare(memErr) == 0)
        {
            secTrack[i] = 2;
            secTrackString[i] = "General Memory Error Section";
        }
        else if (temp.compare(pciExpress) == 0)
        {
            secTrack[i] = 3;
            secTrackString[i] = "PCIe Error Section";
        }
        else if (temp.compare(armProcErr) == 0)
        {
            secTrack[i] = 4;
            secTrackString[i] = "ARM Processor Error Section";
        }

        // j["Sections"][i]["SectionDescriptor"]["SectionType"] =
        // guidDecode(temp);
        j["Sections"][i]["SectionDescriptor"]["SectionType"] =
            secTrackString[i];
        j["Sections"][i]["SectionDescriptor"]["FRUId"] = guidDecode(
            convertToHex(sections[i].fruID, sizeof(sections[i].fruID)));
        if (errorSev.find((int)sections[i].sectionSeverity[0]) !=
            errorSev.end())
        {
            j["Sections"][i]["SectionDescriptor"]["SectionSeverity"] =
                errorSev[sections[i].sectionSeverity[0]];
        }
#ifndef PHASE1
        j["Sections"][i]["SectionDescriptor"]["FRUText"] =
            (convertToHex(sections[i].fruText, sizeof(sections[i].fruText)));
#endif
    }

    // Writing NV CPER Sections into JSON file
    vector<int> regDataPairs(secCount);
    vector<section> secDecode(secCount);
    vector<memErrorSection> decodeMemErr(secCount);
    vector<pcieSection> decodePcieErr(secCount);
    vector<armSection> decodeArmProcErr(secCount);
    for (int i = 0; i < secCount; i++)
    {
        if (secTrack[i] == 1)
        { // condition to check if it is an NV CPER
            memcpy(&secDecode[i],
                   temp + secOffset[i] + sbmrOffset + recordHeaderLen, 32);
            j["Sections"][i]["Section"]["IPSignature"] = (convertToStringAscii(
                secDecode[i].IPSignature, sizeof(secDecode[i].IPSignature)));
#ifndef PHASE1
            j["Sections"][i]["Section"]["ErrorType"] = (charToIntLittleEndian(
                secDecode[i].ErrorType, sizeof(secDecode[i].ErrorType)));
            j["Sections"][i]["Section"]["ErrorInstance"] =
                (charToIntLittleEndian(secDecode[i].ErrorInstance,
                                       sizeof(secDecode[i].ErrorInstance)));
#endif
            if (sectionSeverity.find((int)secDecode[i].Severity[0]) !=
                sectionSeverity.end())
            {
                j["Sections"][i]["Section"]["Severity"] =
                    sectionSeverity[secDecode[i].Severity[0]];
            }
            j["Sections"][i]["Section"]["SocketNumber"] =
                (charToIntLittleEndian(secDecode[i].SocketNumber,
                                       sizeof(secDecode[i].SocketNumber)));
#ifndef PHASE1
            regDataPairs[i] = (charToIntLittleEndian(
                secDecode[i].RegDataPairs, sizeof(secDecode[i].RegDataPairs)));
            j["Sections"][i]["Section"]["NumberOfRegisterDataPairs"] =
                regDataPairs[i];
            j["Sections"][i]["Section"]["InstanceBase"] = addressRepresentation(
                convertToHexLittleEndian(secDecode[i].InstanceBase,
                                         sizeof(secDecode[i].InstanceBase)));
#endif
        }

        // Writing Memory Error Section into JSON
        else if (secTrack[i] == 2)
        { // condition to check if it is a memory error section
            memcpy(&decodeMemErr[i],
                   temp + sbmrOffset + secOffset[i] + recordHeaderLen, 80);
#ifndef PHASE1
            memErrValidationBitsDecode(decodeMemErr[i].validationBits, i);
            memErrErrorStatusTypeDecode((int)decodeMemErr[i].errorStatus[6], i);
            string errorStatusFields[7] = {
                "Address Error Detected",   "Control Error Detected",
                "Data Error Detected",      "Responder Error Detected",
                "Requester Error Detected", "First Error Detected",
                "Overflow Error Detected"};
            int count = 0;
            for (int k = 0; k < 7; k++)
            {
                if (((int)decodeMemErr[i].errorStatus[5] & (0x01 << k)) ==
                    (0x01 << k))
                {
                    j["Sections"][i]["Section"]["ErrorStatus"]
                     ["ErrorStatusField"][count] = errorStatusFields[k];
                    count = count + 1;
                }
            }
            if (count == 0)
            {
                j["Sections"][i]["Section"]["ErrorStatus"]["ErrorStatusField"]
                 [count] = "No Error Status Fields Set";
            }
            j["Sections"][i]["Section"]["PhysicalAddress"] =
                addressRepresentation(convertToHexLittleEndian(
                    decodeMemErr[i].physicalAddress,
                    sizeof(decodeMemErr[i].physicalAddress)));
            j["Sections"][i]["Section"]["PhysicalAddressMask"] =
                addressRepresentation(convertToHexLittleEndian(
                    decodeMemErr[i].physicalAddressMask,
                    sizeof(decodeMemErr[i].physicalAddressMask)));
            j["Sections"][i]["Section"]["Node"] = (charToIntLittleEndian(
                decodeMemErr[i].node, sizeof(decodeMemErr[i].node)));
            j["Sections"][i]["Section"]["Card"] = (charToIntLittleEndian(
                decodeMemErr[i].card, sizeof(decodeMemErr[i].card)));
            j["Sections"][i]["Section"]["Module"] = (charToIntLittleEndian(
                decodeMemErr[i].module, sizeof(decodeMemErr[i].module)));
            j["Sections"][i]["Section"]["BankAddress"] =
                (charToIntLittleEndian(decodeMemErr[i].bankAddress,
                                       sizeof(decodeMemErr[i].bankAddress)));
            j["Sections"][i]["Section"]["BankGroup"] = (charToIntLittleEndian(
                decodeMemErr[i].bankGroup, sizeof(decodeMemErr[i].bankGroup)));
            j["Sections"][i]["Section"]["Device"] = (charToIntLittleEndian(
                decodeMemErr[i].device, sizeof(decodeMemErr[i].device)));
            j["Sections"][i]["Section"]["Row"] = (charToIntLittleEndian(
                decodeMemErr[i].row, sizeof(decodeMemErr[i].row)));
            j["Sections"][i]["Section"]["Column"] = (charToIntLittleEndian(
                decodeMemErr[i].column, sizeof(decodeMemErr[i].column)));
            j["Sections"][i]["Section"]["BitPosition"] =
                (charToIntLittleEndian(decodeMemErr[i].bitPosition,
                                       sizeof(decodeMemErr[i].bitPosition)));
            j["Sections"][i]["Section"]["RequestorID"] = addressRepresentation(
                convertToHexLittleEndian(decodeMemErr[i].requestorID,
                                         sizeof(decodeMemErr[i].requestorID)));
            j["Sections"][i]["Section"]["ResponderID"] = addressRepresentation(
                convertToHexLittleEndian(decodeMemErr[i].responderID,
                                         sizeof(decodeMemErr[i].responderID)));
            j["Sections"][i]["Section"]["TargetID"] = addressRepresentation(
                convertToHexLittleEndian(decodeMemErr[i].targetID,
                                         sizeof(decodeMemErr[i].targetID)));
            if (memErrType.find((int)decodeMemErr[i].memErrType[0]) !=
                memErrType.end())
            {
                j["Sections"][i]["Section"]["MemoryErrorType"] =
                    memErrType[(int)decodeMemErr[i].memErrType[0]];
            }
            else
            {
                j["Sections"][i]["Section"]["MemoryErrorType"] = "Reserved";
            }
            j["Sections"][i]["Section"]["Extended"]["ChipIdentification"] =
                (((int)decodeMemErr[i].extended[0]) >> 5) & 0x07;
            j["Sections"][i]["Section"]["RankNumber"] =
                (charToIntLittleEndian(decodeMemErr[i].rankNumber,
                                       sizeof(decodeMemErr[i].rankNumber)));
            j["Sections"][i]["Section"]["CardHandle"] =
                (charToIntLittleEndian(decodeMemErr[i].cardHandle,
                                       sizeof(decodeMemErr[i].cardHandle)));
            j["Sections"][i]["Section"]["ModuleHandle"] =
                (charToIntLittleEndian(decodeMemErr[i].moduleHandle,
                                       sizeof(decodeMemErr[i].moduleHandle)));
#endif
        }

        // Writing UEFI based PCI Express Error Section into JSON
        // NOTE: THIS SECTION NEEDS TO BE RE REVIEWED FOR ENDIANNESS CHANGES AND
        // BYTE ORDERING. HAS BEEN DEVELOPED WITH NO RELIABLE INPUT. EXPECT
        // MINOR CHANGES.
        else if (secTrack[i] == 3)
        {
            memcpy(&decodePcieErr[i],
                   temp + sbmrOffset + secOffset[i] + recordHeaderLen, 208);
#ifndef PHASE1
            pcieErrValidationBitsDecode(decodePcieErr[i].validationBits, i);
            pcieErrPortTypeDecode((int)decodePcieErr[i].portType[3], i);

            j["Sections"][i]["Section"]["MajorVersion"] =
                (int)decodePcieErr[i].version[2];
            j["Sections"][i]["Section"]["MinorVersion"] =
                (int)decodePcieErr[i].version[3];

            j["Sections"][i]["Section"]["CommandStatus"]["PCICommandRegister"] =
                addressRepresentation(convertToHexLittleEndian(
                    decodePcieErr[i].pciCommandReg,
                    sizeof(decodePcieErr[i].pciCommandReg)));
            j["Sections"][i]["Section"]["CommandStatus"]["PCIStatusRegister"] =
                addressRepresentation(convertToHexLittleEndian(
                    decodePcieErr[i].pciStatusReg,
                    sizeof(decodePcieErr[i].pciStatusReg)));
#endif
            j["Sections"][i]["Section"]["DeviceID"]["VendorID"] =
                addressRepresentation(convertToHexLittleEndian(
                    decodePcieErr[i].vendorID,
                    sizeof(decodePcieErr[i].vendorID)));
            j["Sections"][i]["Section"]["DeviceID"]["DeviceID"] =
                addressRepresentation(convertToHexLittleEndian(
                    decodePcieErr[i].deviceID,
                    sizeof(decodePcieErr[i].deviceID)));
            j["Sections"][i]["Section"]["DeviceID"]["ClassCode"] =
                addressRepresentation(convertToHexLittleEndian(
                    decodePcieErr[i].classCode,
                    sizeof(decodePcieErr[i].classCode)));
            j["Sections"][i]["Section"]["DeviceID"]["FunctionNumber"] =
                addressRepresentation(convertToHexLittleEndian(
                    decodePcieErr[i].functionNumber,
                    sizeof(decodePcieErr[i].functionNumber)));
            j["Sections"][i]["Section"]["DeviceID"]["DeviceNumber"] =
                addressRepresentation(convertToHexLittleEndian(
                    decodePcieErr[i].deviceNumber,
                    sizeof(decodePcieErr[i].deviceNumber)));
            j["Sections"][i]["Section"]["DeviceID"]["SegmentNumber"] =
                addressRepresentation(convertToHexLittleEndian(
                    decodePcieErr[i].segmentNumber,
                    sizeof(decodePcieErr[i].segmentNumber)));
            j["Sections"][i]["Section"]["DeviceID"]["DeviceBusNumber"] =
                addressRepresentation(convertToHexLittleEndian(
                    decodePcieErr[i].deviceBusNumber,
                    sizeof(decodePcieErr[i].deviceBusNumber)));
            j["Sections"][i]["Section"]["DeviceID"]["SecondaryBusNumber"] =
                addressRepresentation(convertToHexLittleEndian(
                    decodePcieErr[i].deviceSecondaryBusNumber,
                    sizeof(decodePcieErr[i].deviceSecondaryBusNumber)));
            j["Sections"][i]["Section"]["DeviceID"]["SlotNumber"] =
                (charToIntLittleEndian(decodePcieErr[i].slotNumber,
                                       sizeof(decodePcieErr[i].slotNumber))) &
                (0xFFF8);
#ifndef PHASE1
            j["Sections"][i]["Section"]["DeviceSerialNumber"]["LowerDW"] =
                addressRepresentation(convertToHexLittleEndian(
                    decodePcieErr[i].lowerDeviceSerialNumber,
                    sizeof(decodePcieErr[i].lowerDeviceSerialNumber)));
            j["Sections"][i]["Section"]["DeviceSerialNumber"]["UpperDW"] =
                addressRepresentation(convertToHexLittleEndian(
                    decodePcieErr[i].upperDeviceSerialNumber,
                    sizeof(decodePcieErr[i].upperDeviceSerialNumber)));
            j["Sections"][i]["Section"]["BridgeControlStatus"]
             ["BridgeSecondaryStatusRegister"] =
                 addressRepresentation(convertToHexLittleEndian(
                     decodePcieErr[i].bridgeSecondaryStatusReg,
                     sizeof(decodePcieErr[i].bridgeSecondaryStatusReg)));
            j["Sections"][i]["Section"]["BridgeControlStatus"]
             ["BridgeControlRegister"] =
                 addressRepresentation(convertToHexLittleEndian(
                     decodePcieErr[i].bridgeControlReg,
                     sizeof(decodePcieErr[i].bridgeControlReg)));
            j["Sections"][i]["Section"]["CapabilityStructure"] =
                addressRepresentation(convertToHexLittleEndian(
                    decodePcieErr[i].capabilityStructure,
                    sizeof(decodePcieErr[i].capabilityStructure)));
            j["Sections"][i]["Section"]["AERInfo"] = addressRepresentation(
                convertToHexLittleEndian(decodePcieErr[i].aerInfo,
                                         sizeof(decodePcieErr[i].aerInfo)));
#endif
        }
        else if (secTrack[i] == 4)
        {
            memcpy(&decodeArmProcErr[i],
                   temp + sbmrOffset + secOffset[i] + recordHeaderLen, 40);
#ifndef PHASE1
            armErrValidationBitsDecode(decodeArmProcErr[i].validationBits, i);
            long int numErrInfo =
                charToIntLittleEndian(decodeArmProcErr[i].errInfoNum,
                                      sizeof(decodeArmProcErr[i].errInfoNum));
            long int numContextInfo = charToIntLittleEndian(
                decodeArmProcErr[i].contexInfoNum,
                sizeof(decodeArmProcErr[i].contexInfoNum));
            long int secLenArm =
                charToIntLittleEndian(decodeArmProcErr[i].armSecLength,
                                      sizeof(decodeArmProcErr[i].armSecLength));
            long int affLvl =
                charToIntLittleEndian(decodeArmProcErr[i].errAffLvl,
                                      sizeof(decodeArmProcErr[i].errAffLvl));
            j["Sections"][i]["Section"]["ErrorInfoNum"] = numErrInfo;
            j["Sections"][i]["Section"]["ContextInfoNum"] = numContextInfo;
            j["Sections"][i]["Section"]["SectionLength"] = secLenArm;
            j["Sections"][i]["Section"]["ErrorAffinityLevel"] = affLvl;
#endif
            j["Sections"][i]["Section"]["SocketNumber"] =
                (int)decodeArmProcErr[i].MPIDR[4];
        }
    }

    // Code fragment to decode the register/data pairs and write into a JSON
    // object
    registers reg[1];
    for (int i = 0; i < secCount; i++)
    {
        if (secTrack[i] == 1)
        {
            for (int k = 0; k < regDataPairs[i]; k++)
            {
                (void)reg[i];
#ifndef PHASE1
                memcpy(&reg[0],
                       temp + sbmrOffset + secOffset[i] + recordHeaderLen + 32 +
                           (16 * k),
                       16);

                j["Sections"][i]["Section"]["Registers"][k]["Address"] =
                    addressRepresentation(convertToHexLittleEndian(
                        reg[0].address, sizeof(reg[0].address)));
                j["Sections"][i]["Section"]["Registers"][k]["Value"] =
                    addressRepresentation(convertToHexLittleEndian(
                        reg[0].value, sizeof(reg[0].value)));
#endif
            }
        }
    }

    // writing all the json objects into the JSON file before closing the file
    jsonFile << j;
    jsonFile.close();
    return 0;
}
