# Firmware Inventory

Generated from the local extracted trees with SHA-256 hashing. The C.50 tree is an OTA reference named for CPH1861; it is not treated as the installed CPH1859 C.50 image.

## Scope and fingerprints

| Set | Provenance | Android / patch | Kernel | Files |
|---|---|---|---|---:|
| C.49 | CPH1859 project reference | Android 9 / 2020-05-05 | 4.4.146+ | 32 |
| C.50 reference | CPH1861-targeted OTA | OTA reference; exact CPH1859 patch not established | 4.4.146+ | 139 |

Available image classes include preloader, LK, boot, recovery, system/vendor/ODM, modem and auxiliary firmware, trust images, partition metadata, and C.50 compressed block-update payloads. The exact-device CPH1859 C.50 partitions, vbmeta, complete extracted C.50 filesystems, kernel config, and source are absent.

## Partition mapping

C.49 mapping is parsed from `MT6771_Android_scatter.txt`; C.50 mapping is parsed from the OTA `scatter.txt` and provides offsets only.

## File manifest

| Set | Relative path | Size (bytes) | SHA-256 | Identified type |
|---|---|---:|---|---|
| c49 | `17065-efuse_oppo6771.xml` | 3057 | `aa9adef10115c9b014553ff1311682cee359a2e93c9d25d48be808c3c514c9c7` | xml |
| c49 | `Efuse.ini` | 201 | `72ccf0f6f993289af8c1ef49be8c4a0449b2bf006d1fbb347e3ab82d7368860b` | text_or_metadata |
| c49 | `MT6771_Android_scatter.txt` | 19588 | `0be7cd2512e42c6c78e358cc1cf1d56f2fab8473f633c7fa48295c2e9fd21355` | partition_scatter |
| c49 | `Projectconfig.xml` | 778 | `9be942966c4ba301df95bc3f6e94090db5ca459acdb59f8be22916b269e67e02` | xml |
| c49 | `all-in-one-signature.bin` | 90464 | `748c275f31a92e7c6686e0a8bf1cc6586adafbc5f98bff2d30c3205cedc9ac8a` | firmware_binary |
| c49 | `auth_sv5.auth` | 2256 | `aa63d7840e8bd3461c1077316e82c86041f50c79892fce59a54dfbf792d8d685` | firmware_binary |
| c49 | `boot.img` | 9780048 | `1a82355e63ca593f28224d4180e070acec562b6d45b76f565c84399a56e1b208` | android_boot_image |
| c49 | `cache.img` | 188612 | `3a234ee17ae6e8cd546a483768fe15e53f695d59ceee4154be3ce83b790d520a` | android_sparse_image |
| c49 | `cam_vpu1.img` | 1652768 | `1a7bafd3f04579dcf06bddb7ce1b69939386c92c9c8205ee7f20b5188056624e` | firmware_binary |
| c49 | `cam_vpu2.img` | 14225552 | `403f0767e98acacb68643b74d9ca44def5231f9467e600ed2f4996ce34b577c8` | firmware_binary |
| c49 | `cam_vpu3.img` | 8765968 | `909f999f4b147e2414090864e2795945adb2dc57eef4e72439f65b69bb86d442` | firmware_binary |
| c49 | `lk.img` | 753984 | `30b48cd52b5d6035819c5580eb4a7f745010042318d1358b46a4f9fd5a37baaa` | firmware_binary |
| c49 | `logo.bin` | 2827248 | `b027c69ffce18e6f873f72165897e7c71577f311c17bb7e57683e8074b6817c7` | firmware_binary |
| c49 | `md1img.img` | 73041472 | `e250145591428a5e0d517a0122a5ea920888aaff7af929fd90345e1661e1feff` | firmware_binary |
| c49 | `odm.img` | 6398160 | `870a24a10c2dd1d655c379b13aca2c4c7459c0b622f185b52244cffdad4dca6d` | android_sparse_image |
| c49 | `odmdtbo.img` | 86672 | `a05aed4f5087ee413ae1d5db002a8a736529ce654b2fce9c9c1f95dfed0bcd61` | firmware_binary |
| c49 | `oppo_custom_17061.img` | 1048576 | `40f35b86d80e54f91a7f1fba493a0ec98b8246439d4612c6c040c59962eca43a` | firmware_binary |
| c49 | `oppo_custom_17066.img` | 1048576 | `2407d565f80788e265142a90d3295b62eb7a51288eaed18a08a2f6700f3f7891` | firmware_binary |
| c49 | `oppo_custom_27065.img` | 1048576 | `0b8815584253335b6b5e9b81bbeeaeb638d90240b309ba25fbe1f29392630344` | firmware_binary |
| c49 | `oppo_custom_27066.img` | 1048576 | `ae507331de2d7f76d62e453ecea7af7d7b3c89028013dee28ce0e63a8704673b` | firmware_binary |
| c49 | `preloader_oppo6771_17065.bin` | 265756 | `afe99890545f60ebb04158d7d327369237ea20241218c35f01f272b94ad1ee1a` | firmware_binary |
| c49 | `recovery.img` | 30483280 | `05cfcf8ffbb59abcbd642a950989cc4d112d1985ad1a4c9eab642ce4e67bdb34` | android_boot_image |
| c49 | `scp.img` | 561072 | `7c6f9def0ae15358d8e5c5fda10d0d17e1df5b6209f769a7489c19b25b61498e` | firmware_binary |
| c49 | `spmfw.img` | 40576 | `8a93bc930d0b719f17f27266da9b905b1d203353393013802012b75e560130e1` | firmware_binary |
| c49 | `sspm.img` | 496464 | `905eb19ed19acd5bf347cd9b263327c32fae2cc8119f0f513cce8d94c61e09d0` | firmware_binary |
| c49 | `system.img` | 3859190712 | `3c28df6690940df4a60431a6a3bcb756e3c4936acda9678f99406584e48b5f03` | android_sparse_image |
| c49 | `system.sig` | 4560 | `1f0c6e5bac1a1d47e7d9e6a7fc92626a6cec4381078b54d36809e2c1af02e9dd` | partition_signature_blob |
| c49 | `tee.img` | 507216 | `57ef7ed1ca50b31893c821d0432b645eade81b2261c742bdf31cdbd8a90f7ddd` | firmware_binary |
| c49 | `userdata.img` | 2147644116 | `3c385ce5f04ec97e982449e2d8d31c62cde334b0b6e96f937c0bc1382166b851` | android_sparse_image |
| c49 | `userdata.sig` | 4176 | `eeed61ffd639b8251798eb4aacc9bb5f55ae2d73a071cc1223ca291610c19947` | partition_signature_blob |
| c49 | `vendor.img` | 815395192 | `cd5123491d641226583fb017ccc993a9be1c11e44cd49823bce6e3308c169bc5` | android_sparse_image |
| c49 | `vendor.sig` | 3856 | `a20079236560b06e4257155c428faa47832eaa8430306d3a4e9714df00064fa7` | partition_signature_blob |
| c50_reference | `META-INF/CERT.RSA` | 1522 | `b71df384fca111c1b743e86fc811f42a1bb61869d0ece972c9aff46408fe2f41` | data |
| c50_reference | `META-INF/CERT.SF` | 16026 | `e6a3f6908064118827ca2847fdd463418ab145ddd517cb69c3ccb18b9014d477` | text_or_metadata |
| c50_reference | `META-INF/MANIFEST.MF` | 14749 | `3346a4c278f7c83bb73cd3c243731d7b7c1792e54202f3a348ebbb90349dd9a5` | text_or_metadata |
| c50_reference | `META-INF/com/android/metadata` | 289 | `e519e916080ee302fa807dbdd39cce23f0efac55da2b2c73639783bf8bee17f2` | text_or_metadata |
| c50_reference | `META-INF/com/android/otacert` | 1424 | `83f8de04b9af5d5d19df4f7c879bd9ac25cbe648966e2f02094d3f5346c9d9a1` | data |
| c50_reference | `META-INF/com/google/android/update-binary` | 1817440 | `37ebe5da778bad17010e85a460c54a55f5068441e7172fdb450b683856208f38` | data |
| c50_reference | `META-INF/com/google/android/updater-script` | 13800 | `5c53cf5b160a87edcc9d0f118caa980ba92c30aaba0cb3c20e64aa329e9bf945` | text_or_metadata |
| c50_reference | `boot.img` | 9786192 | `44d9b48d5c49cde8b9df5eb9d67b8feefe4adf381bfb56cc9455e4bae23f98c5` | android_boot_image |
| c50_reference | `cam_vpu1.img` | 1652768 | `f2a8b00bc4de9bb544387487df0cd48d6f494d3db9f078b3c0e2f74b4181ef35` | firmware_binary |
| c50_reference | `cam_vpu2.img` | 14225552 | `924f354ecf9cb497100b4f1dc84084eb770bf29b97b95711cae9539d2c98a2c0` | firmware_binary |
| c50_reference | `cam_vpu3.img` | 8765968 | `f1d400e92cbc22ba0b9e7781bdd50296fd536e421bad6c23571a0854fe34476c` | firmware_binary |
| c50_reference | `compatibility.zip` | 7231 | `39c8cfaef5dd9352cd0a1d488cf43e9f48f5c84faed42940a25491f41eff9aa6` | zip_archive |
| c50_reference | `data/engineermode/otapushfile` | 900 | `a7eee5b36e6ffe3a9b1efd153a7f2f60265890547b0db9117f03cc8387af7f10` | text_or_metadata |
| c50_reference | `data/engineermode/persistnameext_common_ID_common.txt` | 37 | `95034d9c362fee78771758cadeec1508917cb20b6f9f305d82f15da4324adc4f` | text_or_metadata |
| c50_reference | `data/engineermode/persistnameext_common_IN_common.txt` | 39 | `698c9c7add7eaf8e10ba9845f2ab3292ed79340d55a0d8cac4a2d207b87c3f53` | text_or_metadata |
| c50_reference | `data/engineermode/persistnameext_common_MY_common.txt` | 18 | `1001f57ccbb083571918e8258ef8b409bfae65e036ea9d42c3e0337a108b56c9` | text_or_metadata |
| c50_reference | `data/engineermode/persistnameext_common_SG_common.txt` | 18 | `1001f57ccbb083571918e8258ef8b409bfae65e036ea9d42c3e0337a108b56c9` | text_or_metadata |
| c50_reference | `data/engineermode/persistnameext_common_TH_common.txt` | 18 | `1001f57ccbb083571918e8258ef8b409bfae65e036ea9d42c3e0337a108b56c9` | text_or_metadata |
| c50_reference | `data/engineermode/persistnameext_common_TW_common.txt` | 18 | `1001f57ccbb083571918e8258ef8b409bfae65e036ea9d42c3e0337a108b56c9` | text_or_metadata |
| c50_reference | `data/engineermode/persistpathext_common_ID_common.txt` | 55 | `ffc24a174813b9c79a2389b0d6bef2b30c3822f41d0b9b5fea3fbb7c6b21c8f3` | text_or_metadata |
| c50_reference | `data/engineermode/persistpathext_common_IN_common.txt` | 57 | `c5175bd4de69912bc7d8089732298d014f70ed5546d1cf6559fc5796db2ad32a` | text_or_metadata |
| c50_reference | `data/engineermode/persistpathext_common_MY_common.txt` | 27 | `ca3bd5becc5bc66e72c3e796e61ce91bf83528c7f914ebe43ccf4d8518126475` | text_or_metadata |
| c50_reference | `data/engineermode/persistpathext_common_SG_common.txt` | 27 | `ca3bd5becc5bc66e72c3e796e61ce91bf83528c7f914ebe43ccf4d8518126475` | text_or_metadata |
| c50_reference | `data/engineermode/persistpathext_common_TH_common.txt` | 27 | `ca3bd5becc5bc66e72c3e796e61ce91bf83528c7f914ebe43ccf4d8518126475` | text_or_metadata |
| c50_reference | `data/engineermode/persistpathext_common_TW_common.txt` | 27 | `ca3bd5becc5bc66e72c3e796e61ce91bf83528c7f914ebe43ccf4d8518126475` | text_or_metadata |
| c50_reference | `data/reserve/com.realmecomm.app.apk` | 14863920 | `cb2066dbb06b513037ab21f169006cd1fc7523f0a3fedb828fd334abb41ca0b0` | android_package |
| c50_reference | `data/reserve/com.realmestore.app.apk` | 8015149 | `399e7715ed65bbbaca8be6b6d34354c96fe64cdbb206d4e0b4589a9b34e3532f` | android_package |
| c50_reference | `data/reserve/com.zhangyue.read.apk` | 18023871 | `8af8925699067f25d4e258be4a37a30b8a4643509ca848ea2b40cc454eacf1ef` | android_package |
| c50_reference | `data_update_patch/app/realmeLink.apk` | 27439622 | `492f405d78482e93cb929cb3b150336cf7f289c34f644e02d254f88af438da06` | android_package |
| c50_reference | `data_update_patch/conf/engineermode/.sd.txt` | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | data |
| c50_reference | `data_update_patch/conf/engineermode/MediaResourceConfig/config.xml` | 186 | `66c074f85df2898d7f2c44d31bcccecdd22366f1f1a3dc357393fad4ba102862` | xml |
| c50_reference | `data_update_patch/conf/engineermode/appchannel_common_ID_common.txt` | 84 | `599d884ac4c30ca9fa527087499495929ae483aa1db35b10bf06d379c032e8bb` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/appchannel_common_MY_common.txt` | 41 | `15e863412a4bd9219a02f4dab9e4191aec3cc2b05878cd4ce74a3150d20aa9d1` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/appchannel_common_PH_common.txt` | 18 | `a7bc9346b3f36c4d01522d45908ba36b9ed01121eae4cb9fbab40f84360e7106` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/appchannel_common_SG_common.txt` | 41 | `15e863412a4bd9219a02f4dab9e4191aec3cc2b05878cd4ce74a3150d20aa9d1` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/appchannel_common_TH_common.txt` | 41 | `15e863412a4bd9219a02f4dab9e4191aec3cc2b05878cd4ce74a3150d20aa9d1` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/appchannel_common_TW_common.txt` | 38 | `1cf0d1f10f7afddcb2740f6e0096389013e68dd0794b3f29e03144e767c5ed0b` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/appchannel_common_VN_common.txt` | 38 | `116ecd8dcfbe9051523e662a91ff136cebcd923ecdfe3660735934f2d7d5523d` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/data_version` | 9 | `7dff722c262995584ef719e4e4f0ceeee585062cd72b826fc0576eac1b8d1642` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/gboard_common_-EUEX_common.txt` | 241 | `1e7018fd3a1c15418daa7e1822680abde863e5e87ec138681631191dfbe46e0c` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/gboard_common_-ID_common.txt` | 264 | `83d597b9627d750e7ca4fe4fa8faa09ebdd8e442313ed1856160b209a7064ccb` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/gboard_common_-IN_common.txt` | 195 | `9faa6bb29f7936898602c25c26af43c33cda11b15a0f7119b9c3408a87d069e2` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/gboard_common_-JP_common.txt` | 264 | `83d597b9627d750e7ca4fe4fa8faa09ebdd8e442313ed1856160b209a7064ccb` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/gboard_common_-MM_common.txt` | 264 | `83d597b9627d750e7ca4fe4fa8faa09ebdd8e442313ed1856160b209a7064ccb` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/gboard_common_-MY_common.txt` | 264 | `83d597b9627d750e7ca4fe4fa8faa09ebdd8e442313ed1856160b209a7064ccb` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/gboard_common_-SG_common.txt` | 264 | `83d597b9627d750e7ca4fe4fa8faa09ebdd8e442313ed1856160b209a7064ccb` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/gboard_common_-TH_common.txt` | 264 | `83d597b9627d750e7ca4fe4fa8faa09ebdd8e442313ed1856160b209a7064ccb` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/gboard_common_-TW_common.txt` | 264 | `83d597b9627d750e7ca4fe4fa8faa09ebdd8e442313ed1856160b209a7064ccb` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/gboard_common_-VN_common.txt` | 264 | `83d597b9627d750e7ca4fe4fa8faa09ebdd8e442313ed1856160b209a7064ccb` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/gboard_common_EUEX_common.txt` | 581 | `bf2dd7bb74adb057b6f1490241ffa30e25e830bab2764d0f13a5b9c56127f7e3` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/gboard_common_ID_common.txt` | 20 | `308b5c0157b1715f3cdc933163d39605334f8818551709044e0191c977f311cb` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/gboard_common_IN_common.txt` | 270 | `b2f472a82896e13a160855212052ae8dce0e8907158c5c715b3c03db7c1145cf` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/gboard_common_JP_common.txt` | 10 | `ba40e96769611012033dc5bf3f962240b8a38bbc16e2a6c81ad9778a68128ff7` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/gboard_common_MY_common.txt` | 23 | `ec0e26594646d77ef16af66be464415d6c46a58c8f72b238659baf80da9753ef` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/gboard_common_SG_common.txt` | 46 | `8c25cb37209ac70d0aef02000d6fbee4d2da31cc0a99eaa1088afe4576a975d2` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/gboard_common_TH_common.txt` | 20 | `b9ce002559865b4ec600f5a02d780869c5d24cd59760b59726551d8bf04a9cdd` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/gboard_common_VN_common.txt` | 20 | `40bbeba53d40ae17badaa2a2e0afc74046348083d434d9fe0e1001bd0ebb4459` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/gboard_common_common_common.txt` | 23 | `dbd4e1e529117af13d03738082efc6d53cdbccd6bc974ac603dbec147895ce01` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/otapushfile` | 900 | `a7eee5b36e6ffe3a9b1efd153a7f2f60265890547b0db9117f03cc8387af7f10` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/package_channel.txt` | 891 | `503bcaea44d3a135ff621e6245f25eb6583319487b726e61350df4cadefc3d66` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistname` | 1242 | `16fad869af1c2d05a2e0addf0279081a2960a3a2dc5875ed03c9049c781a3a39` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistname_common_-EUEX_common.txt` | 55 | `d8f46722ed941e31452bb6f49cc58e06a0ef17b640ef0fe27e57b97a3c2712be` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistname_common_-RU_common.txt` | 16 | `e75d2bd188361cd94e5bc85c51a6357ab8e338df32d0ae40975ef50f323d9b5b` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistname_common_EUEX_common.txt` | 20 | `7456822233f9e27456884e551f192548da5bc9da6374c66ea43028de42468c9c` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistname_common_ID_common.txt` | 84 | `853b1c03665ed72b6bbaecc39098b83f20ca6872365bd1e0cb8b5abb20f59007` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistname_common_IN_common.txt` | 72 | `e8c99f6c4279198cb81739863a8661fa9b835aa17c7afe916e5ff0cffc611981` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistname_common_MY_common.txt` | 37 | `8c03e6d874f205095a9365bb4d58bf3f1eb0dd230c2a5556226d40667d74beb8` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistname_common_PH_common.txt` | 19 | `29b51b2ba602cb44bec7de3d6ba4b8fa9325dd7e8ca97afe26625b4261c8fdf5` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistname_common_SG_common.txt` | 37 | `8c03e6d874f205095a9365bb4d58bf3f1eb0dd230c2a5556226d40667d74beb8` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistname_common_TH_common.txt` | 37 | `8c03e6d874f205095a9365bb4d58bf3f1eb0dd230c2a5556226d40667d74beb8` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistname_common_TW_common.txt` | 33 | `76a17db9c23f59045a24f56940531a386dbaf363fc6adecbd5649ac30cfb5282` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistname_common_VN_common.txt` | 34 | `834c4032daa000c98a0666cd574f4b2ab43a1994dacf8c43f126bc69d018d80f` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistname_common_common_APT.txt` | 15 | `4f72a1a478a480ff23d56e1762d076a79d49843d486681e7b43ee89e65ae34ec` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistname_common_common_CELCOM.txt` | 20 | `e524e24864d1006c6dc3fc64741b336184719850032dd1c66d8270faca889df0` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistname_common_common_DIGI.txt` | 31 | `7f0ba8549fba303d972245d09e85a94d0eb1c0854e21c15bac72af40ecc67813` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistname_common_common_FET.txt` | 161 | `a6ba58e18b9e416ed57f8ab88e934a435f8792504b02a14dfe1c77f39a0d6999` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistname_common_common_MAXIS.txt` | 18 | `467b1e0989c5355a7262fd7cb67400bdaba062a1f34395fc0708882d4b35161f` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistname_common_common_OPTUS.txt` | 25 | `90e73e0671c1f64d164fc4c6c7b415b3ad8a562780d205f4bfa2d50b45b131d6` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistname_common_common_STARHUB.txt` | 39 | `9824b73a85c75968db2775c7ec2eb27182ba43a1991b3d838220a9c9bba2874e` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistname_common_common_TWM.txt` | 50 | `63e87b8045e7c3eb0de3acab1cf9e3586cf508615f5124c694803663e23723aa` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistname_common_common_VIRGIN.txt` | 28 | `6b03de02f677039c7e36fabd76f2d03cfe449a64326d61adc760bbc9e4689982` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistname_common_common_VODAFONE.txt` | 27 | `7dcc97e73168c144003ebec0f7d5c356a8fec14109d8c0c2f0c5b651550961b7` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistname_common_common_common.txt` | 199 | `ececf9258050bf71a6a1893fe2d1b4cafa4fc646f3c03640eff06aaf4c4f5b98` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistnameext_common_ID_common.txt` | 37 | `95034d9c362fee78771758cadeec1508917cb20b6f9f305d82f15da4324adc4f` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistnameext_common_IN_common.txt` | 39 | `698c9c7add7eaf8e10ba9845f2ab3292ed79340d55a0d8cac4a2d207b87c3f53` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistnameext_common_MY_common.txt` | 18 | `1001f57ccbb083571918e8258ef8b409bfae65e036ea9d42c3e0337a108b56c9` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistnameext_common_SG_common.txt` | 18 | `1001f57ccbb083571918e8258ef8b409bfae65e036ea9d42c3e0337a108b56c9` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistnameext_common_TH_common.txt` | 18 | `1001f57ccbb083571918e8258ef8b409bfae65e036ea9d42c3e0337a108b56c9` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistnameext_common_TW_common.txt` | 18 | `1001f57ccbb083571918e8258ef8b409bfae65e036ea9d42c3e0337a108b56c9` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistpath` | 1639 | `faabe7f1eb17c3fe770ed00663ccde3c36612a2a2a4e8f2090b0f4de0596ddc5` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistpath_common_-EUEX_common.txt` | 77 | `6ab798ec523e154a220d85b223e1176273e0b8d1b37a328a2304302465f3f51e` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistpath_common_-RU_common.txt` | 20 | `d13b8dc412b7f360d56de47017e4ec89500a3156215df423b81f6f826b05f243` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistpath_common_EUEX_common.txt` | 29 | `b7ede8866bedf0952a3ad543c9ed486a437ea836ca23bf7e2ed47428b3d769ad` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistpath_common_ID_common.txt` | 129 | `b19edd7ae4f231cd0a4285ef70f5b8cf33ee840acda3260411c4f562268da0f3` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistpath_common_IN_common.txt` | 99 | `0c4a7add1346c0f42276d58836ad92f6bc4c9825947336a01949f2aa662d49d4` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistpath_common_MY_common.txt` | 55 | `b6c062e762f7d080074792460f61edd73e4683f37312da8700835e85e1aa5177` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistpath_common_PH_common.txt` | 28 | `1248d9646869995bcfef3ca653f3eacf6452239ffc4e63c30d8b6ea9863422c4` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistpath_common_SG_common.txt` | 55 | `b6c062e762f7d080074792460f61edd73e4683f37312da8700835e85e1aa5177` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistpath_common_TH_common.txt` | 55 | `b6c062e762f7d080074792460f61edd73e4683f37312da8700835e85e1aa5177` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistpath_common_TW_common.txt` | 51 | `7e6bbc51f4f07704c2daafc4197843bab80bc54f3e78ed155b5c56885a9be377` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistpath_common_VN_common.txt` | 52 | `2dfb9119e28b7f6457c3bf47cb97811e682db48ff340c9c48bad539df0a7cee3` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistpath_common_common_APT.txt` | 24 | `a9a9bfbfe797393d7f067a253af207eac860bdf1a9f333cd029ed4438a5ac754` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistpath_common_common_CELCOM.txt` | 29 | `967d6cf830effb81d7244e4ed32a2601c06a5d95830e6992ffdd0a9e1c33e172` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistpath_common_common_DIGI.txt` | 40 | `8bba5b54dfec4b64c59d4bac8b12b3f56d4d9348032fd6e01fb0cdc16855c3e2` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistpath_common_common_FET.txt` | 233 | `0681ddfc32f776c6056fc8860bc07d4a23b35b15d6f0b0ef9dff040ec3fed35b` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistpath_common_common_MAXIS.txt` | 27 | `f418080626db1c5f8475ef031fc57735a9d884825c23716f4711b89d3ecc33b0` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistpath_common_common_OPTUS.txt` | 34 | `d861209a504fa60f31168650286c452bbb3def60c71818d5125abb17984ec808` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistpath_common_common_STARHUB.txt` | 57 | `a7628cfba4a169f08fd842afb01eab4adeac795551925be27d1802e2dcef7551` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistpath_common_common_TWM.txt` | 68 | `15e8b145ccd9e9f1de1040d94cbc097bfc0dc8c98cb6a18e3fd25ad104d5614c` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistpath_common_common_VIRGIN.txt` | 37 | `24ae40416a1fb4a1d36685a529e03d6ccc885a8a0b3529ad799d519a4814550f` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistpath_common_common_VODAFONE.txt` | 36 | `2c28cbba0bff23056912e77b36df98894459153c560da23a44ab1526c0c20b5d` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistpath_common_common_common.txt` | 253 | `69ac86bf23984252df36292b26f87923a1a5c7d9d50581fc6b204851aff67bb1` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistpathext_common_ID_common.txt` | 55 | `ffc24a174813b9c79a2389b0d6bef2b30c3822f41d0b9b5fea3fbb7c6b21c8f3` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistpathext_common_IN_common.txt` | 57 | `c5175bd4de69912bc7d8089732298d014f70ed5546d1cf6559fc5796db2ad32a` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistpathext_common_MY_common.txt` | 27 | `ca3bd5becc5bc66e72c3e796e61ce91bf83528c7f914ebe43ccf4d8518126475` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistpathext_common_SG_common.txt` | 27 | `ca3bd5becc5bc66e72c3e796e61ce91bf83528c7f914ebe43ccf4d8518126475` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistpathext_common_TH_common.txt` | 27 | `ca3bd5becc5bc66e72c3e796e61ce91bf83528c7f914ebe43ccf4d8518126475` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/persistpathext_common_TW_common.txt` | 27 | `ca3bd5becc5bc66e72c3e796e61ce91bf83528c7f914ebe43ccf4d8518126475` | text_or_metadata |
| c50_reference | `data_update_patch/conf/engineermode/reserve_app_name` | 2052 | `1cb2ac98c9789915c342e393a2f99325dd31757405a9dec9b7d2b83bd5e46be1` | text_or_metadata |
| c50_reference | `lk.img` | 753984 | `58cd19a9647610146f07bcf2ad5a1b0cd3056ce967c784bb37ea347669f5e563` | firmware_binary |
| c50_reference | `logo.bin` | 2827248 | `a6f983938ad700067b841ce4b6e39c5a629b1bc930ad81165e4ba7a09a7723b1` | firmware_binary |
| c50_reference | `md1img.img` | 73041472 | `e250145591428a5e0d517a0122a5ea920888aaff7af929fd90345e1661e1feff` | firmware_binary |
| c50_reference | `odmdtbo.img` | 86672 | `b88c5204b1017826fa801f0fd23bf3b79740f268afb7e0437b313d37ed25f7a6` | firmware_binary |
| c50_reference | `oppo_update_script.sh` | 1200 | `81ae8bbab6c30430716d26c10ccbe728a957ba8d3172d837599ecb32b53b79ca` | text_or_metadata |
| c50_reference | `preloader.img` | 267804 | `2de60eda847de8ea3ae44368fc905f57dd63a842a3c7ad455f0fd1c326ebaeca` | firmware_binary |
| c50_reference | `preloader_emmc.img` | 267804 | `2de60eda847de8ea3ae44368fc905f57dd63a842a3c7ad455f0fd1c326ebaeca` | firmware_binary |
| c50_reference | `preloader_ufs.img` | 269852 | `eb290e2e8b4f8cdb1a03e4b98c94deba1a36d2eb59c4959f5e3b1265898d9981` | firmware_binary |
| c50_reference | `scatter.txt` | 851 | `76eccecebc5ea9cdc89d701cfd96d4d8b429e6a65df18df96a2f8e8b485d3ac6` | partition_scatter |
| c50_reference | `scp.img` | 561072 | `8bd0afa2dc4d1f4537bc2032f804e5d999b7a0812eeec78955df953f37eb7b04` | firmware_binary |
| c50_reference | `spmfw.img` | 40576 | `8828e6655d5f4e340582c40163cf6f6df1dc1915be6339f67c6106ed8685b6b1` | firmware_binary |
| c50_reference | `sspm.img` | 496464 | `90f2e73ae4dc2a8dfcef80d7fd595e76753d3156c858b303d4e7f81de247c6c2` | firmware_binary |
| c50_reference | `system.new.dat.br` | 1916609304 | `71dc86bbc910b5b59ffc1519744010c2c84297d1a254f3c45d3ebc4fa6a8af97` | brotli_block_update_payload |
| c50_reference | `system.patch.dat` | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | data |
| c50_reference | `system.transfer.list` | 19763 | `41a0be49ff66b1909ce51c4e18e6653048337fa3a7d81dfa41d02a1265e51d79` | block_update_transfer_list |
| c50_reference | `tee.img` | 507216 | `2d9b44e239332b8faf384ea143ea0f0177171141a99317753fa96efb034a4eb8` | firmware_binary |
| c50_reference | `type.txt` | 1 | `6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b` | data |
| c50_reference | `vendor.new.dat.br` | 334914427 | `36cbc5d654fe5a7bc689fac215006517bef2ac9d2ee02d072078e0617e6cb188` | brotli_block_update_payload |
| c50_reference | `vendor.patch.dat` | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | data |
| c50_reference | `vendor.transfer.list` | 4333 | `daf041627ded341f7d9995e362a0056001dac782417d05fca682a3bd44741b64` | block_update_transfer_list |

## Reproduction

```text
PYTHONPATH=src:scripts python3 scripts/generate_firmware_inventory.py
```
