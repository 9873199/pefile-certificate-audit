Public reference: https://raw.githubusercontent.com/MicrosoftDocs/win32/docs/desktop-src/Debug/pe-format.md

1154: Attribute certificates can be associated with an image by adding an attribute certificate table. The attribute certificate table is composed of a set of contiguous, quadword-aligned attribute certificate entries. Zero padding is inserted between the original end of the file and the beginning of the attribute certificate table to achieve this alignment. Each attribute certificate entry contains the following fields.
1155: 
1156: 
1157: 
1158: | Offset       | Size                         | Field                       | Description                                                                                                |
1159: |--------------|------------------------------|-----------------------------|------------------------------------------------------------------------------------------------------------|
1160: | 0<br/> | 4<br/>                 | dwLength<br/>         | Specifies the length of the attribute certificate entry. <br/>                                       |
1161: | 4<br/> | 2<br/>                 | wRevision<br/>        | Contains the certificate version number. For details, see the following text.<br/>                   |
1162: | 6<br/> | 2<br/>                 | wCertificateType<br/> | Specifies the type of content in bCertificate. For details, see the following text.<br/>             |
1163: | 8<br/> | See the following<br/> | bCertificate<br/>     | Contains a certificate, such as an Authenticode signature. For details, see the following text.<br/> |
1164: 
1165: 
1166: 
1167:  
1168: 
1169: The virtual address value from the Certificate Table entry in the Optional Header Data Directory is a file offset to the first attribute certificate entry. Subsequent entries are accessed by advancing that entry's dwLength bytes, rounded up to an 8-byte multiple, from the start of the current attribute certificate entry. This continues until the sum of the rounded dwLength values equals the Size value from the Certificates Table entry in the Optional Header Data Directory. If the sum of the rounded dwLength values does not equal the Size value, then either the attribute certificate table or the Size field is corrupted.
1170: 
1171: For example, if the Optional Header Data Directory's Certificate Table Entry contains:
1172: 
1173: 
1174: ```C++
1175: virtual address = 0x5000
1176: size = 0x1000
1177: ```
1178: 
1179: 
1180: 
1181: The first certificate starts at offset 0x5000 from the start of the file on disk. To advance through all the attribute certificate entries:
1182: 
1183: 1.  Add the first attribute certificate's dwLength value to the starting offset.
1184: 2.  Round the value from step 1 up to the nearest 8-byte multiple to find the offset of the second attribute certificate entry.
1185: 3.  Add the offset value from step 2 to the second attribute certificate entry's dwLength value and round up to the nearest 8-byte multiple to determine the offset of the third attribute certificate entry.
1186: 4.  Repeat step 3 for each successive certificate until the calculated offset equals 0x6000 (0x5000 start + 0x1000 total size), which indicates that you've walked the entire table.
1187: 
1220: The WIN\_CERTIFICATE structure's **bCertificate** member contains a variable-length byte array with the content type specified by **wCertificateType**. The type supported by Authenticode is WIN\_CERT\_TYPE\_PKCS\_SIGNED\_DATA, a PKCS\#7 **SignedData** structure. For details on the Authenticode digital signature format, see [Windows Authenticode Portable Executable Signature Format](https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx).
1221: 
1222: If the **bCertificate** content does not end on a quadword boundary, the attribute certificate entry is padded with zeros, from the end of **bCertificate** to the next quadword boundary.
1223: 
1224: The **dwLength** value is the length of the finalized WIN\_CERTIFICATE structure and is computed as:
1225: 
1226: `dwLength = offsetof(WIN_CERTIFICATE, bCertificate) + (size of the variable-length binary array contained within bCertificate)`
1227: 
1228: This length should include the size of any padding that is used to satisfy the requirement that each WIN\_CERTIFICATE structure is quadword aligned:
1229: 
1230: ` dwLength += (8 - (dwLength & 7)) & 7;`
1231: 
1232: The **Certificate Table size**-specified in the **Certificates Table** entry in the [Optional Header Data Directories (Image Only)](#optional-header-data-directories-image-only)- includes the padding.
1233: 

Normal v2 fixtures include padding in dwLength. Unaligned dwLength interpretation is excluded from scoring.
