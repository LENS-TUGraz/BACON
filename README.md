<p align="center">
  <picture>
    <source width="150" media="(prefers-color-scheme: dark)" srcset="assets/logo_white.svg">
    <source width="150" media="(prefers-color-scheme: light)" srcset="assets/logo_black.svg">
    <img alt="Shows a black logo in light color mode and a white one in dark color mode." src="https://user-images.githubusercontent.com/25423296/163456779-a8556205-d0a5-45e2-ac17-42d089e3c3f8.png">
  </picture>
  <h1 align="center">BACON: Improving Broadcast Audio Authentication</h1>
</p>

This repository contains the source code for BACON, a novel Bluetooth core specification compliant mechanism for the authentication of Broadcast Isochronous Groups (BIGs). Authenticated BIGs are able to provide data authenticity for broadcast isochronous streams as well as control subevents used to disseminate control information to all receiver devices in communication range. 
Further information on BACON can be found in the [corresponding paper](https://www.carloalbertoboano.com/documents/gasteiger24bacon.pdf) by Theo Gasteiger, Pericle Perazzo, Markus Schuß, Carlo Alberto Boano, Fikret Basic, Gianluca Dini and Kay Römer in Proc. of the IEEE MILCOM, 2024.

In order to execute the BACON broadcaster and receiver applications, the included `BACON.patch` must be applied to [nRF Connect SDK v2.6.0](https://github.com/nrfconnect/sdk-nrf/releases/tag/v2.6.0) and [Zephyr v3.5.99-ncs1](https://github.com/nrfconnect/sdk-zephyr/releases/tag/v3.5.99-ncs1) compiled for Nordic Semiconductor nRF52840 development kits.
