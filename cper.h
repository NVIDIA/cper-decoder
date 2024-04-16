/*
 * SPDX-FileCopyrightText: Copyright (c) 2023-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
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

#include <bitset>
#include <fstream>
#include <include/CLI/CLI.hpp>
#include <include/json.hpp>
#include <iostream>
#include <map>
#include <string>


// Constants and magic numbers
const int recordHeaderLen = 0;
const int sbmrOffset = 4; // 4 bytes of information present before header
const int headerSize = 128; // Standard record header size
const int secDescSize = 72; // Standard section descriptor size
const int signatureEndMarker = 255; // Each byte of the signature end must be 0xFF which is 255 in int

/**
* Consists of strings to match each section type
* @note: The section type (GUID) is in the order it is stored in memory in the log file
**/
const std::string nvda("f244526d1227ec11bea7cb3fdb95c786"); // NVIDIA CPER Section Type
const std::string memErr("1411bca5646fde4eb8633e83ed7c83b1"); // General Memory Error Section Type
const std::string pciExpress("54e995d9c1bb0f43ad91b44dcb3c6f35"); // PCI Express Error Section Type
const std::string armProcErr("163d9ee111bce4119caac2051d5d46b0"); // ARM Processor Error Section Type

// structure to store the Record Header information as different fields (Refer
// UEFI spec -> Appendix N)
#pragma pack(1)
struct header {
  unsigned char formatVersion[1];
  unsigned char formatType[1];
  unsigned char eventDataLength[2];
  unsigned char signatureStart[4];
  unsigned char Revision[2];
  unsigned char SignatureEnd[4];
  unsigned char SectionCount[2];
  unsigned char ErrorSeverity[4];
  unsigned char ValidationBits[4];
  unsigned char RecordLength[4];
  unsigned char Timestamp[8];
  unsigned char PlatformID[16];
  unsigned char PartitionID[16];
  unsigned char CreatorID[16];
  unsigned char NotificationType[16];
  unsigned char RecordID[8];
  unsigned char Flags[4];
  unsigned char PersistenceInfo[8];
  unsigned char Reserved[12];
};

// structure to store the content of 1 section descriptor as different fields
#pragma pack(1)
struct sectionDescriptor {
  unsigned char sectionOffset[4];
  unsigned char sectionLength[4];
  unsigned char revision[2];
  unsigned char validationBits[1];
  unsigned char reserved[1];
  unsigned char flags[4];
  unsigned char sectionType[16];
  unsigned char fruID[16];
  unsigned char sectionSeverity[4];
  unsigned char fruText[20];
};

// structure to define common fields of the NVIDIA CPER section
#pragma pack(1)
struct section {
  unsigned char IPSignature[16];
  unsigned char ErrorType[2];
  unsigned char ErrorInstance[2];
  unsigned char Severity[1];
  unsigned char SocketNumber[1];
  unsigned char RegDataPairs[1];
  unsigned char Reserved[1];
  unsigned char InstanceBase[8];
};

// structure to define the register and data pairs
#pragma pack(1)
struct registers {
  unsigned char address[8];
  unsigned char value[8];
};

// structure to define the Memory Error Section
#pragma pack(1)
struct memErrorSection {
  unsigned char validationBits[8];
  unsigned char errorStatus[8];
  unsigned char physicalAddress[8];
  unsigned char physicalAddressMask[8];
  unsigned char node[2];
  unsigned char card[2];
  unsigned char module[2];
  unsigned char bankGroup[1];
  unsigned char bankAddress[1];
  unsigned char device[2];
  unsigned char row[2];
  unsigned char column[2];
  unsigned char bitPosition[2];
  unsigned char requestorID[8];
  unsigned char responderID[8];
  unsigned char targetID[8];
  unsigned char memErrType[1];
  unsigned char extended[1];
  unsigned char rankNumber[2];
  unsigned char cardHandle[2];
  unsigned char moduleHandle[2];
};

// structure to define the PCI Express Error Section
#pragma pack(1)
struct pcieSection{
  unsigned char validationBits[8];
  unsigned char portType[4];
  unsigned char version[4];
  unsigned char pciCommandReg[2];
  unsigned char pciStatusReg[2];
  unsigned char reserved[4];
  unsigned char vendorID[2];
  unsigned char deviceID[2];
  unsigned char classCode[3];
  unsigned char functionNumber[1];
  unsigned char deviceNumber[1];
  unsigned char segmentNumber[2];
  unsigned char deviceBusNumber[1];
  unsigned char deviceSecondaryBusNumber[1];
  unsigned char slotNumber[2];
  unsigned char devReserved[1];
  unsigned char lowerDeviceSerialNumber[4];
  unsigned char upperDeviceSerialNumber[4];
  unsigned char bridgeSecondaryStatusReg[2];
  unsigned char bridgeControlReg[2];
  unsigned char capabilityStructure[60];
  unsigned char aerInfo[96];
};

// structure to define the ARM Processor Error Section
#pragma pack(1)
struct armSection{
  unsigned char validationBits[4];
  unsigned char errInfoNum[2];
  unsigned char contexInfoNum[2];
  unsigned char armSecLength[4];
  unsigned char errAffLvl[1];
  unsigned char reserved[3];
  unsigned char MPIDR[8];
  unsigned char MIDR[8];
  unsigned char runningState[4];
  unsigned char psciState[4];
};