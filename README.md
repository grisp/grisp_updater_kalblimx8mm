# grisp_updater_kalblimx8mm

GRiSP Software Updater HAL for Kontron AL/BL iMX8M Mini

## Build

    $ rebar3 compile

## Configuration

To use the Kontron HAL with grisp_updater, you need the following configuration:

```erlang
[
    {grisp_updater, [
        {system, {grisp_updater_kalblimx8mm, #{}}},
        {sources, [
            {grisp_updater_tarball, #{}},
            {grisp_updater_http, #{
                backend => {grisp_updater_kalblimx8mm, #{}}
            }}
        ]}
    ]}
]
```

## Update Medium

The Kontron AL/BL iMX8M Mini HAL for grisp_updater can update either the
SD card or the on-board eMMC. It can be forced to update the eMMC from the
SD card with the `sys.config` option `force_emmc_update`.

When set to `true`, all update operation on an sdcard will perform A/B
software update the eMMC instead of the SD card.

Note that the `force_emmc_update` cannot be changed at runtime because
it is used when grisp_updater is started, chaning it later will not have
the intended effect.

Example application environment:

```erlang
[
    {grisp_updater_kalblimx8mm, [
        {force_emmc_update, true}
    ]}
].
```
