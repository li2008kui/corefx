// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Test.Cryptography;

namespace System.Security.Cryptography.X509Certificates.Tests.CertificateCreation
{
    internal static class TestData
    {
        internal static readonly RSAParameters RsaBigExponentParams = new RSAParameters
        {
            Modulus = (
                "AF81C1CBD8203F624A539ED6608175372393A2837D4890E48A19DED369731156" +
                "20968D6BE0D3DAA38AA777BE02EE0B6B93B724E8DCC12B632B4FA80BBC925BCE" +
                "624F4CA7CC606306B39403E28C932D24DD546FFE4EF6A37F10770B2215EA8CBB" +
                "5BF427E8C4D89B79EB338375100C5F83E55DE9B4466DDFBEEE42539AEF33EF18" +
                "7B7760C3B1A1B2103C2D8144564A0C1039A09C85CF6B5974EB516FC8D6623C94" +
                "AE3A5A0BB3B4C792957D432391566CF3E2A52AFB0C142B9E0681B8972671AF2B" +
                "82DD390A39B939CF719568687E4990A63050CA7768DCD6B378842F18FDB1F6D9" +
                "FF096BAF7BEB98DCF930D66FCFD503F58D41BFF46212E24E3AFC45EA42BD8847").HexToByteArray(),

            Exponent = new byte[] { 0x02, 0x00, 0x00, 0x04, 0x41 },

            D = (
                "64AF9BA5262483DA92B53F13439FD0EF13012F879ABC03CB7C06F1209904F352" +
                "C1F223519DC48BFAEEBB511B0D955F6167B50E034FEA2ABC590B4EA9FBF0C51F" +
                "9FFEA16F7927AE681CBF7358452BCA29D58705E0CAA106013B09A6F5F5911498" +
                "D2C4FD6915585488E5F3AD89836C93C8775AFAB4D13C2014266BE8EE6B8AA66C" +
                "9E942D493466C8E3A370F8E6378CE95D637E03673670BE4BCACE5FCDADD238D9" +
                "F32CA35DE845776AC4BF36118812328C493F91C25A9BD42672D0AFAFDE0AF7E6" +
                "19078D48B485EF91933DDCFFB54587B8F512D223C81894E91784982F3C5C6587" +
                "1351F4655AB023C4AD99B6B03A96F9046CE124A471E828F05F8DB3BC7CCCF2D1").HexToByteArray(),

            P = (
                "E43A3826A97204AE3CD8649A84DB4BBF0725C4B08F8C43840557A0CD04E313AF" +
                "6D0460DDE69CDC508AD043D72514DA7A66BC918CD9624F485644B9DEEAB2BE0E" +
                "112956D472CF0FD51F80FD33872D2DCC562A0588B012E8C90CE7D254B94792C6" +
                "E7A02B3CCAA150E67A64377ACC49479AD5EB555493B2100CB0410956F7D73BF5").HexToByteArray(),

            Q = (
                "C4DD2D7ADD6CA50740D3973F40C4DEBDBAB51F7F5181ABAE726C32596A3EDD0A" +
                "EE44DAADDD8A9B7A864C4FFDAE00C4CB1F10177BA01C0466F812D522610F8C45" +
                "43F1C3EF579FA9E13AE8DA1A4A8DAE307861D2CEAC03560279B61B6514989883" +
                "FE86C5C7420D312838FC2F70BED59B5229654201882664CEFA38B48A3723E9CB").HexToByteArray(),

            DP = (
                "09ECF151F5CDD2C9E6E52682364FA5B4ED094F622E4031BF46B851358A584DCC" +
                "B5328B0BD9B63589183F491593D2A3ACAD14E0AACDA1F181B5C7D93C57ED26E6" +
                "2C9FC26AF37E4A0644ECE82A7BA8AED88FF1D8E9C56CC66385CDB244EB3D57D1" +
                "7E6AD420B19C9E2BEE18192B816265B74DA55FA3825F922D9D8E835B76BF3071").HexToByteArray(),

            DQ = (
                "89B33B695789174B88368C494639D4D3267224572A40B2FE61910384228E3DBD" +
                "11EED9040CD03977E9E0D7FC8BFC4BF4A93283529FF1D96590B18F4EABEF0303" +
                "794F293E88DC761B3E23AFECB19F29F8A4D2A9058B714CF3F4D10733F13EA72B" +
                "BF1FBEC8D71E106D0CE2115F3AD2DE020325C3879A091C413CD6397F83B3CB89").HexToByteArray(),

            InverseQ = (
                "7C57ED74C9176FBA76C23183202515062C664D4D49FF3E037047A309DA10F159" +
                "0CE01B7A1CD1A4326DC75883DFF93110AB065AAED140C9B98176A8810809ADEC" +
                "75E86764A0951597EF467FA8FD509181CD2E491E43BE41084E5BE1B562EE76E9" +
                "F92C9AB1E5AEAD9D291A6337E4DE85BDE67A0D72B4E55ADCF207F7A5A5225E15").HexToByteArray()
        };

        internal static readonly byte[] TestRootPfx = (
            "3082098D0201033082094D06092A864886F70D010701A082093E0482093A3082" +
            "0936308205A706092A864886F70D010701A08205980482059430820590308205" +
            "8C060B2A864886F70D010C0A0102A08204F6308204F2301C060A2A864886F70D" +
            "010C0103300E04087E248FBF7F2308EC020207D0048204D0A46072998856D7A5" +
            "8A75C6BCB4CD3F48CA0E77C0B180FC8E122371C57FB35DD251DF6B3A42465F63" +
            "D309BB1E84019E2578F8F0170FCC04E574B2CF7F476C40BCAAB7E1781318B47B" +
            "88832562E1DEA2725C8A1066D60A5990055B64AB5C295B85351BD55032FC3E66" +
            "6C6F468A5B0B08A7B84AF4AE1C0518977D072AC120BF58583FA6351F720E9E5B" +
            "EAE103B5E36B46AE97A07D3A19A96E4292D3646AC2386E07EB22C09D136C4390" +
            "AB407D6CA1D9F5A757EC109C4BCDF8AAAB5C57394251A37E29A0E15BCCE56020" +
            "EDF7D266182242E3AE66FAAFC485CFA6FA5E5915235E77DD1DE61486AFDFCBE5" +
            "D78FD23A9025B0E4A9B939629B86A5792B22E7FE14AEDBFAD21AE2528BA195E6" +
            "F8758BE3EC5493EBBA46011792883D84311F82058D6573AEC78FEF522B78F846" +
            "B424CEBC64E069871784BDEAD55F722E38590FB35B4534B80EB2DD1DFC90DB8D" +
            "F9957F019AA949F50D0AA37076F7C2C620841E972D52A44E979C3DB614A597B9" +
            "865A7FFC6285E314003F01AB146F75394B84D8FD88CA2FE910395AAC0834E83B" +
            "051BE2733B5AFE4A2E91F7D32278BD3B74F2E404E0B325623A514442582675D8" +
            "F8DE7AF3EB84EC327031B2C89607003B63CE64EF262468547490FB5B2DC0C075" +
            "7BF247CE4892D5FD9BB76226457BD4F5F7E6B91321FAA0320CE281C161CCD666" +
            "9C7915743F835FF4CA3FBE4D688BA0EB5FDCD8C395C8A33CC35AB3B9739E3970" +
            "B6671EC05573D19E5516B456B657996235EB3877FDC08393B6DDD4FE0264877B" +
            "47EFAF8DE39BCE7D35AC6E4C4F577A206C38602079B2ACEE3CC0346D5DFCE097" +
            "3E996450C0219B41DE0C9A00E95404C0B02C0B99A27884335CD8543BDCCBE0D9" +
            "CC629719BD6B6FC2A4C7DBD5ABDAC3136C3E1F71651681D4D4CA37FDE8D28395" +
            "4A44C59AE1104379E03C137765C9118518613197343BB15A35B595A969B89BDB" +
            "6B1D57C428E51DDB1864CB46D46373955051E243EE4680904E7DC72C52BE39F4" +
            "5E4274416AAE7A6C702515840D78CF8450FAA8150BE97AECD1B3511796E235EB" +
            "3C9916D3C636F33422C0509FEC618457D810974BF280B858ECD42FB175E92566" +
            "52DADFCCCB5AF5B76FA02C452B9F1E27E0354949324D613D24E51F596BC38EA2" +
            "996E3919F53332E7893A620E50636954B727B98206ABF0F7A57199F81171D04D" +
            "AD1684035C502D7225949D54F1F8E17F7FBFAF457FBC2EDE3A234D6959FD59FF" +
            "8A24D038CDC288390DE09711ECA790F38D80D20BC1D44A89FBF220B78F4946CE" +
            "C0F9C53D6ADFBDAD480168E2A30C3FA43750BD9514438BBC0B14C630D5EFB03B" +
            "060C836BEA3AAB44FCDB4016D9F1CB0792000A6808C72F22191D5A44C12DB770" +
            "E78A9ECA7DF072A770876E67CFC1153A128187F3C27DE3D9B5BB8C4816E5BCB0" +
            "24D5444803672919DDAF2AF6BFF5D7C7466920969DF1371E7FEF95067B5ADCBA" +
            "05B70DB7EB015F734BB9D9E13D7C49A6AADFFC5303C8F0338A7CBF416D8A7C3C" +
            "A554F6825247ADFF7933274D1D3AC5F1847D1CD9043DB8F176DBD77A2C9F9B1D" +
            "09174D41E5561E4F525B6D4827F02B3B2221983446ECAFDC4705ED327C284241" +
            "DD649676BD391508557056DAE20B24B99FB97AC0F407C15B003806EBE161CBE2" +
            "D2783C32E58B76FBC57E79996593F7E29FB12ABAE1A36605AEC5CEEA4F6B992F" +
            "621B981D13FC0F851B40D116A940DE0340812BACF0ECE7EDB47F6D4EAA9DE134" +
            "C4545DA0445EE38F318182301306092A864886F70D0109153106040401000000" +
            "306B06092B0601040182371101315E1E5C004D006900630072006F0073006F00" +
            "66007400200045006E00680061006E0063006500640020004300720079007000" +
            "74006F0067007200610070006800690063002000500072006F00760069006400" +
            "650072002000760031002E00303082038706092A864886F70D010706A0820378" +
            "308203740201003082036D06092A864886F70D010701301C060A2A864886F70D" +
            "010C0106300E0408B8B7F6E865AE8048020207D080820340C0F41125DBE00774" +
            "1176330B5D854A6683CDD05224D365A3EF199C2FB0C8F143C4EE06EE76D558B9" +
            "C26AAB30055CE986D0CB7AC64F04C23CDD3FF60E7C6C44D27A77BEC8DDABFBCA" +
            "B817CDA8FCC588B0E63C506BC6631F8CEA35AF8CDCA4FA03630651A745681977" +
            "8E626B15C16A70231F889FF56950A339494E249E9F5172FDACDB4041EFA193BD" +
            "B15708680EE089EC7FC972FA22613F71C49497CB10511CD94A32766161691170" +
            "D2D5E2D8660C21BBA40B1C36BE379CEE15BE2CF1B9C1DA544BB4E15182BE5573" +
            "3CE74C6ED03BC924B7E712C7A99664B2FAB7B221BB9236CF3820D681DC2DF0E8" +
            "7EADFADA0C02E6A9AEBBF5EA688D53014D62C6C629D951F6B398B819DCC06E3C" +
            "C82DA872D770619EFF3E1EDE3D794D81585BA4F4C6572E596AA667E593097A2E" +
            "9A4295245630D0AB1B1111AB25D1B26543CB8B8A7D91A31D239EE5C95D2829CC" +
            "716EB3BB967F8912E125F574403B07D0565C63582CAB109B3D45CAFB4D0B5922" +
            "1BC9C28D618A40E8D0C045A911F59A4694C0A1E94317CB0CD9F21EA7CADE5DFB" +
            "700AD50A4A33A89DB6D22DC8A730C37C088F4604018F561ADCAAECD797294DD8" +
            "32C197F006D71746D1A480484BEA770A3B719C7F3DCFE12C5900691160152236" +
            "0602907807E5FB99D3B36B44C0F0AA0C2EBC18C5F36FFA60C22E4AF0EB43DBDB" +
            "780300E895D7FB49CC367CEB8D75F390D70B78731D530B2E13776ABD668A3440" +
            "5FAA0DA1B4C4D217716C832B7F270B48CCC5E4AEF90A0F0A3EAE57ACBCD1FB48" +
            "BE7D32F133EB640631873D957E1FE4253FF5C4E0FAEB0ECDB51171FB5982FDA8" +
            "F96D142F1BF791AF898E90745D8F2E03C3B63854B3F42FCFBA1BFA81BB6D6803" +
            "4B53A33BE3BB1781D25BBEF2A170A51E2219F1E5F7844E3D351F3A035520881F" +
            "9FE4FE5B955E183C3B8A43493297C738B4A86CA2756B4E5C35523FCD96F5FAF2" +
            "AA5DC4C3EDCB55A0117D9F4831D1A03CA31BB3F05D8D417F22FE159E044D34BA" +
            "5B81602CB07D07A9A5D21E04B37E8F0E0DCF4322C7DD85E81572BDE99CEED914" +
            "9F42F28ADE9F0FB7E6F40F9D4F25580B83B4E42B72D47EF9A7E01B457358917A" +
            "344647E46C6651F0940219EEE147F97A5832DC34E65D85EBA87E19F919B2F912" +
            "09A0714E730FBCA0084825CBA1E5CD81FBF81F6703C0A0EA3037301F30070605" +
            "2B0E03021A0414981F41899876012208199DE8A2CD40B13F0BBAD904140DE238" +
            "68F9026EBC941A2A7344289AD7A2CA7A4B").HexToByteArray();

        internal static readonly byte[] BigExponentCASignedPfx = Convert.FromBase64String(
            "MIILWQIBAzCCCx8GCSqGSIb3DQEHAaCCCxAEggsMMIILCDCCBb8GCSqGSIb3DQEH" +
            "BqCCBbAwggWsAgEAMIIFpQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYwDgQIB95K" +
            "0OIesikCAggAgIIFeKZHfMDkRGK0e7JASBIZ1RIZbZTl1UwJBunEZcyWwnhFmeYt" +
            "kk6jTESyK+DyG+25BbTBsrlPFFYWXI+80pqSON2yXDZJB0v2wOS0fMTLaqSkRo4W" +
            "85xeYPcud9/gf0ZjXRXM3kUgkOx6cYlZrs4N9LXx7WYKIC9n8LX+3nzqN7Wz21WJ" +
            "rP5xxpvZn8xWhsO3zzaCDa0QypWriTompvxwzY2Cxi797hwzxUIRYGYhZmVkapZ+" +
            "op8u6A4qjxTfv6CtlE6a2Q0u+LaP8mysFYx+Br8FuG6ZQsi3fUkC1Jt1tBhGN1uP" +
            "BGeDznijKbsOJtEk1YIitb513AnXZXwXSlzCHnq0byPLC4AHvBa6kQA42Jaux7iO" +
            "yj2fuf6FZHrPg/RC3MnxMgISpo+1WL0APHqCoDbsObPNHXXkF3A6XoxD+50cf29f" +
            "Y/dz5iTgsIYd7UESQk+LxKkXXRFU5HcwBRWyy4s7SycQGAI1I2yMPgm0yCA18mCz" +
            "HzqFZVb+/4xBOkEDDPX9QjBZ7raADtvx7qpgQbXhF9m3qt/9mUs4htFLk4QGi5/z" +
            "OPRt/Z0Aufs2GtblZ3ihUdynKYtuXdFZu97xJBZPMVu7bwpWDg9sho1dbi+dhbgq" +
            "fNk+Py6a079pQbtmwBRAm31zFTIJtmfB+08HFc85kdtOCR8xtXDbHNHLp/M3vEsM" +
            "o2FlduIyuuRooOIVjOcAsOiO7Fvf9gftE/t3YaTidFoT4Mqj9DS6EO40rXlDTU7C" +
            "h6kC1fZt8/3jAaoomwMaUhwWpAHfvJOsDBpp+hNRoa5lsg6xLWNlCWlwOOLZnoCf" +
            "HfpusAvz0Wco8vhAMZfjqn4DwlqMOSZzr2oZlxCdqz9Pm1iX8cSRy2bCz2vYemnN" +
            "IIK7Z6G/AVdXKwAuKF+XuXeFIAVhwsZ4lrXgz2sFBRT80vEys7GBahOe2/jsc6kK" +
            "l+B9Iz9W1J3iv3Oua+gni5jrSJUNQ5ih9NOHfdHLqKXH5Jbd99SVlq+KWHO3YOLH" +
            "yBA7F+Kqr+TPTs1yn3D22BDghKYYqWlTImMa7psyulfz0p7+IpgRZwl6I09EzXF4" +
            "iOS9SZWg1zZ1oV72mGaU9itPA+hGm24mkuW51J02WURfeRwVfHiVD3AbCuQHyYi4" +
            "goKwVdohDjFaGyezuYUOI51EJitmFtBIO/ly5ms8fdOMqdfdSPVPNrqdeVmSzhI0" +
            "IQznD9s3M2JKmNmJp0Hqy8xp2gO4gVDFm+GbFPEiKdq+cBe6rkYz08SEXwCySa09" +
            "zsVCWF2q9lkZ/eQSfeoLgxWffpzGPc4ZURwynnVOWlhdJxOHkvaoRswsuMeUhiGN" +
            "oRNwfvNbiB2Jw+9iBrbK90k+S+8Q+uLvpgd/AqaN4ZRhRYLRVfSbIaqun+ON0ooC" +
            "u51FGPWhkUvzfi4MLEkBTOF6ZD3rFAdeMZ140byHh3BnLYiT7ojp7hr/gOV5IwTZ" +
            "E7JHQhfoJVTy4dllQ3sve1dRdi2OFv5J6bVczyBRQGwdO7RHRdsVMxEOh5RICRO1" +
            "UrK3HTphgkGR6DgVZ9VVyaVLJfJqE9W+cZH2+VMnLwhUb2KnAoiIiE3CCt27SLIO" +
            "1gybfx7ETVZix1KP94mnSQrjm68Ou22jiqBnDL/j1DF1xTLriWNfMtY6JVXHIm3h" +
            "cWeJW/RagZkkAyC6s1Ql3hdtShweME9vlDZ5ixBcT9hrz652IWYjo7FguUw74kV3" +
            "FX4j4SxKJqpcLD+Kjp8X9CqvdFUtljRgrJyrcovPGg7l9RY+CV1JnTNMHBhzzrM6" +
            "Cv805Neth55k3s1h3V9lnKEW8GwrUP//C8T+tNVS3tIu1eR3NH7T6u2nqb2qf0HU" +
            "OrfrCdQAzD/JmTn3k6jeAH0KY13EMIIFQQYJKoZIhvcNAQcBoIIFMgSCBS4wggUq" +
            "MIIFJgYLKoZIhvcNAQwKAQKgggTuMIIE6jAcBgoqhkiG9w0BDAEDMA4ECOvzL0Zp" +
            "rXPCAgIIAASCBMghD/GpmnaBCq/MYmztbd/xSIcFHxQmRm2jQ+GEpoOXVrbhIIeF" +
            "mDXCmMCDp2t5ejqfHR2eUz9Y6FIEf8LYD5JUkk7uVYh3nanOKnjfwgrbCAxcKkF0" +
            "GaafoLhqcwxAhJMbtlGR5O8dSmARSjRlG198OnxVWrtG8CQaO291b45GrQIDLoal" +
            "aVL2eDW/JtVfImfGSdZiwmV9f0hvxsSs63kHqAEIaZ42J06uYS2tyfN/R/fs9gAU" +
            "tS2FGLYs8c3aNgMlLALsGc9Mxtoe3YOms3KqevNWscPX+eZtVC8FV1ZpPRKQHkHz" +
            "eUD+CuBYr3yEP8ZK7y7oYeGg1qhKfy8Kp1LYehri6KjlCGZARbZdDVMrs10CMGgc" +
            "NlLL0nt13B+KYfuIED+0tTs18oPPpwPhc347lJN8idahrJV6wt5YumF4BAyD/wIo" +
            "SFrSApRhGMLgNKRP+WqLTzzyCpZPI8nCVkUHgPV4W3S0M55sKa/x8CfV5hy2X6Pq" +
            "LqrebdUzW0ipfV9bjUFmeGXWNSBtTAjQdgf6lH6GB9KUEcNUagf6j9mLHAJmY78l" +
            "kkP7NeU7LtpglWPw9w+Ysu1dnq14pvBcrpgoWD0n4fzUN2O/sYFpolaEYUL/Rvhf" +
            "SPcW4WNh9LmhbTvQSh/qpW480AL6BKTzVyWFv4ZIOJuekOaq4/DETkEtAKENlxBB" +
            "pcoBkMRtQ4sQfbYkeivDRMEC/280OJARMsIIJccB8ANIBRUKThazDKBb4n1po0En" +
            "do6HmnT0V6q5u3McKKQCdvx/Ym+oiuMH4b/DSaMEc79+K2oeKCxLHb0D7t/o3rWk" +
            "JO+6FSbQDQDTm9S4GdYoTIRRk6oIVoO3EZ2N5jkqrEGMYkLHq87wi02wc4j/yUfq" +
            "ZU9f4sRnsg9oIqKuNx7RXfwY07NuMD9xn/T9EXLImhgll44y9s8DfV35v2YiIGCf" +
            "j3l43ZKD/rqNEybIo9jeEdH56Xjf0W/BhxfpKRz3ekH4Q93nDuLLPt9h8U3UZAui" +
            "Wy6z/dYLu6TRhAbVjRhUeO3WTbWbe+BB8kTewsL1o2GRvJ/i631Gq2+rqbekyouL" +
            "BgjHXEZ0XsnRF3A9SIPxg1KFOTu+bapmWWAsdSwIZSbZJu8zTFZnzb+zXdg1Rmgn" +
            "ndyKaVnJzxChEmX8fx0FsLdWhr/h3DLXAcGOPulZTi1r6nIfxgGgFc0R5HERz8Fu" +
            "WkwiUOProTtbxttQTYuTlUzZrf8zB4OY1KUiCjPZouMXG5NUdTdK1vxk0kVcKD2H" +
            "lSXAQCd8OL/6d9QKhInZRu1Uwcl8Hsdt65gpI4ArldCaRrg2B9GUjb5eYyg7YSvv" +
            "POv08Wewsm3hl78BX8LDfyjG0FnXgdKowymBmuKUEDKm1EK7ynFF6w5QwHYsT46k" +
            "UJdOpWVQ4t/QJZEriEyAA+HHbe0krOcdTyZCINwFIjvom6CcQeoxWKeEO6BrCjl2" +
            "VHDnkRxIgL5qpeF0WxoPBfTn+9GcNvoDxTTdEIY2wGKVPUH+glzsSSHKHCqps/N/" +
            "AE+Q2OipxW8xR9CXY06x9NY5VL9fhv7APeIl7UUHfIgtUp8Gfbt8sv4OdGOGKbLA" +
            "OBJSMUbafJ/HKOdoWh0wPBzykd6zNANqy9q2FweRqNJFAFExJTAjBgkqhkiG9w0B" +
            "CRUxFgQUMbUrj2SiXZKagoVs1WeCUx+L+lcwMTAhMAkGBSsOAwIaBQAEFF8B8YSE" +
            "lYGOmPhAaJ3hTUd72cNEBAhnLe76J/+ALAICCAA=");

        internal static readonly byte[] BigExponentPkcs10Bytes = (
            "30820311308201F902010030818A310B30090603550406130255533113301106" +
            "03550408130A57617368696E67746F6E3110300E060355040713075265646D6F" +
            "6E64311E301C060355040A13154D6963726F736F667420436F72706F72617469" +
            "6F6E3120301E060355040B13172E4E4554204672616D65776F726B2028436F72" +
            "6546582931123010060355040313096C6F63616C686F737430820124300D0609" +
            "2A864886F70D010101050003820111003082010C0282010100AF81C1CBD8203F" +
            "624A539ED6608175372393A2837D4890E48A19DED36973115620968D6BE0D3DA" +
            "A38AA777BE02EE0B6B93B724E8DCC12B632B4FA80BBC925BCE624F4CA7CC6063" +
            "06B39403E28C932D24DD546FFE4EF6A37F10770B2215EA8CBB5BF427E8C4D89B" +
            "79EB338375100C5F83E55DE9B4466DDFBEEE42539AEF33EF187B7760C3B1A1B2" +
            "103C2D8144564A0C1039A09C85CF6B5974EB516FC8D6623C94AE3A5A0BB3B4C7" +
            "92957D432391566CF3E2A52AFB0C142B9E0681B8972671AF2B82DD390A39B939" +
            "CF719568687E4990A63050CA7768DCD6B378842F18FDB1F6D9FF096BAF7BEB98" +
            "DCF930D66FCFD503F58D41BFF46212E24E3AFC45EA42BD884702050200000441" +
            "A03F303D06092A864886F70D01090E3130302E302C0603551D11042530238704" +
            "7F00000187100000000000000000000000000000000182096C6F63616C686F73" +
            "74300D06092A864886F70D01010B050003820101003BCAE7E02D3A828435110C" +
            "8A65197FF1A027EC5ACA37EBE29B6E7093A4BDCA9BDA8E244DC05846AA9F186D" +
            "2EBBDF6474BB09ECF5A3C11F3A7E56D9D489C3D4AE2DCF5D52ABFCDFED6D4623" +
            "AF7C7D2E52A189BC4A0BFC5EB96EC158A96B292DF6E4ADCAE5233A7E1598444E" +
            "23F732526B71172266E45706F90EFAB0945A75D446F0A6547C788DD81AD6F4D1" +
            "E7FD0E8884083AF52003D9CD38B3A140F2E552CF3FBF0B4C771E5745C6DA6F26" +
            "DCFD0FEB87B9FDD2F4724A09DE1FB4C55E439F43C6E37A866BA19494B210D294" +
            "699B3C957C6DD22E9B63DBAE3B5AE62919F0EA3DF304C7DD9E0BBA0E7053605F" +
            "D066A788426159BB937C58E5A110461DC9364CA7CA").HexToByteArray();
    }
}
