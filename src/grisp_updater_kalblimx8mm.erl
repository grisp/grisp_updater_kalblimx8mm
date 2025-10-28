-module(grisp_updater_kalblimx8mm).

-behaviour(grisp_updater_system).
-behaviour(grisp_updater_http).


%--- Includes ------------------------------------------------------------------

-include_lib("kernel/include/logger.hrl").
-include_lib("grisp_updater/include/grisp_updater.hrl").


%--- Exports -------------------------------------------------------------------

% Behaviour grisp_updater_system callbacks
-export([system_init/1]).
-export([system_get_systems/1]).
-ifdef(EMULATE_HARDWARE).
-export([system_get_global_target/1]).
-else. % EMULATE_HARDWARE is undefined
-export([system_get_updatable/1]).
-endif.
-export([system_update_init/2]).
-export([system_prepare_update/2]).
-export([system_prepare_target/4]).
-export([system_set_updated/2]).
-export([system_cancel_update/1]).
-export([system_validate/1]).
-export([system_updated/1]).
-export([system_terminate/2]).

% Behaviour grisp_updater_http callbacks
-export([http_init/1]).
-export([http_connection_options/2]).


%--- Records -------------------------------------------------------------------

-record(uboot_env, {
    raw_env :: map(),
    architecture :: binary(),
    platform :: binary(),
    active :: grisp_updater_system:system_id() | removable,
    valid :: grisp_updater_system:system_id(),
    upgrading :: boolean(),
    rollback :: boolean(),
    bootcount :: non_neg_integer(),
    bootlimit :: non_neg_integer()
}).

-record(sys_state, {
    uboot_env :: #uboot_env{},
    kernel_args :: map(),
    metadata :: map(),
    target :: target(),
    next :: grisp_updater_system:system_id()
}).

-record(http_state, {
    tls_trans_opts :: gun:transport_opts()
}).


%--- Macros --------------------------------------------------------------------

-define(ALLOY_ENV_VER, <<"1">>).
-define(GLOBAL_DEVICE, <<"/dev/mmcblk0">>).
-define(SYSTEM_A_DEVICE, <<"/dev/mmcblk0p3">>).
-define(SYSTEM_B_DEVICE, <<"/dev/mmcblk0p4">>).
-define(SYSTEM_R_DEVICE, <<"/dev/mmcblk1p3">>).
-define(UBOOT_ENV_CONFIG, [
    {?GLOBAL_DEVICE, 16#00428400, 16#10000},
    {?GLOBAL_DEVICE, 16#00438400, 16#10000}
]).
-define(CONNECT_TIMEOUT, 3000).


%--- Behaviour grisp_updater_source Callback -----------------------------------

system_init(_Opts) ->
    ?LOG_INFO("Initializing Kontron AL/BL iMX8M Mini update system interface", []),
    maybe
        {ok, UBootEnv} ?= uboot_load_env(),
        {ok, KernelArgs} ?= kernel_load_args(),
        ok ?= validate_active(UBootEnv, KernelArgs),
        {ok, Target} ?= init_target(),
        {ok, Next} ?= next_active(UBootEnv),
        {ok, #sys_state{
            uboot_env = UBootEnv, kernel_args = KernelArgs,
            target = Target, next = Next}}
    end.

system_get_systems(#sys_state{uboot_env = #uboot_env{active = Active, valid = Valid}, next = Next}) ->
    {Active, Valid, Next}.

-ifdef(EMULATE_HARDWARE).

% During emulation, we need global target as we are writing to a file
system_get_global_target(#sys_state{target = Target}) -> Target.

-else. % EMULATE_HARDWARE is undefined

% On real hardware we don't allow global targets, and we select the updatable
% system explicitly based on the active and valid systems

system_get_updatable(#sys_state{uboot_env = #uboot_env{active = Active, valid = 0}})
  when Active =:= 0; Active =:= removable ->
    {ok, 1, #target{device = ?SYSTEM_B_DEVICE, offset = 0}};
system_get_updatable(#sys_state{uboot_env = #uboot_env{active = Active, valid = 1}})
  when Active =:= 1; Active =:= removable ->
    {ok, 0, #target{device = ?SYSTEM_A_DEVICE, offset = 0}};
system_get_updatable(#sys_state{}) ->
    {error, not_updatable}.

-endif.

system_update_init(State = #sys_state{uboot_env = UBootEnv}, Info) ->
    ?LOG_INFO("Starting Kontron AL/BL iMX8M Mini software update", []),
    Meta = maps:with([product, version, vcs, uuid, author,
                      description, architecture, platform], Info),
    maybe
        ok ?= validate_firmware(Meta, UBootEnv),
        {ok, State#sys_state{metadata = Meta}}
    end.

system_prepare_update(#sys_state{uboot_env = #uboot_env{valid = SysId}}, SysId) ->
    {error, cannot_update_current_valid_system};
system_prepare_update(#sys_state{uboot_env = #uboot_env{active = SysId}}, SysId) ->
    {error, cannot_update_current_active_system};
system_prepare_update(#sys_state{uboot_env = UBootEnv} = State, SysId)
  when SysId =:= 0; SysId =:= 1 ->
    maybe
        {ok, UBootEnv2} ?= uboot_prepare_update(UBootEnv, SysId),
        {ok, State#sys_state{uboot_env = UBootEnv2}}
    end.

system_prepare_target(_State, SysId, _SysTarget,
                      #file_target_spec{context = system, path = Path}) ->
    {ok, #target{device = kernel_path(Path, SysId), offset = 0, size = undefined}};
system_prepare_target(_State, _SysId,
                      #target{offset = SysOff, size = SysSize} = SysTarget,
                      #raw_target_spec{context = system, offset = ObjOffset})
  when ObjOffset >= 0, ObjOffset < SysSize ->
    {ok, SysTarget#target{offset = SysOff + ObjOffset}}.

system_set_updated(#sys_state{uboot_env = #uboot_env{active = Active, valid = 0} = UBootEnv,
                              metadata = Meta} = State, 1)
  when Active =:= 0; Active =:= removable ->
    maybe
        {ok, UBootEnv2} ?= uboot_finalize_update(UBootEnv, Meta, 1),
        {ok, State#sys_state{uboot_env = UBootEnv2}}
    end;
system_set_updated(#sys_state{uboot_env = #uboot_env{active = Active, valid = 1} = UBootEnv,
                              metadata = Meta} = State, 0)
  when Active =:= 1; Active =:= removable ->
    maybe
        {ok, UBootEnv2} ?= uboot_finalize_update(UBootEnv, Meta, 0),
        {ok, State#sys_state{uboot_env = UBootEnv2}}
    end;
system_set_updated(#sys_state{}, _SysId) ->
    {error, unexpected_update_state}.

system_cancel_update(#sys_state{uboot_env = #uboot_env{active = removable}}) ->
    {error, cannot_cancel_update_from_sdcard};
system_cancel_update(#sys_state{uboot_env = #uboot_env{upgrading = false}}) ->
    {error, no_upgrade_pending};
system_cancel_update(#sys_state{uboot_env = #uboot_env{active = Active, valid = Active} = UBootEnv} = State) ->
    % Canceling from the updater system
    maybe
        {ok, UBootEnv2} ?= uboot_cancel_update(UBootEnv, other_system(Active)),
        {ok, State#sys_state{uboot_env = UBootEnv2}}
    end;
system_cancel_update(#sys_state{uboot_env = #uboot_env{active = Active} = UBootEnv} = State) ->
    % Canceling from the updated system
    maybe
        {ok, UBootEnv2} ?= uboot_cancel_update(UBootEnv, Active),
        {ok, State#sys_state{uboot_env = UBootEnv2}}
    end.

system_validate(#sys_state{uboot_env = #uboot_env{active = removable}}) ->
    {error, cannot_validate_from_sdcard};
system_validate(#sys_state{uboot_env = #uboot_env{upgrading = false}}) ->
    {error, no_upgrade_pending};
system_validate(#sys_state{uboot_env = #uboot_env{active = Active, valid = Active}}) ->
    % Validating from the updater system
    {error, reboot_needed};
system_validate(#sys_state{uboot_env = #uboot_env{active = Active} = UBootEnv} = State) ->
    % Validating from the updated system
    maybe
        {ok, UBootEnv2} ?= uboot_validate_update(UBootEnv, Active),
        {ok, State#sys_state{uboot_env = UBootEnv2}}
    end.

system_updated(State) ->
    ?LOG_INFO("Kontron AL/BL iMX8M Mini software update done", []),
    {ok, State}.

system_terminate(_State, _Reason) ->
    ?LOG_INFO("Terminating GRiSP update system interface", []),
    ok.


%--- Behaviour grisp_updater_http Callback -------------------------------------

http_init(Opts) ->
    {ok, #http_state{
        tls_trans_opts = prepare_tls_transport_options(Opts)
    }}.

http_connection_options(State, Url) ->
    DefOpts = #{connect_timeout => ?CONNECT_TIMEOUT},
    case uri_string:parse(Url) of
        #{scheme := <<"https">>, host := Host} = Parts ->
            Hostname = unicode:characters_to_list(Host),
            Port = maps:get(port, Parts, 443),
            Opts = tls_options(State, Host, DefOpts),
            {ok, Hostname, Port, Opts, State};
        #{scheme := <<"http">>, host := Host} = Parts ->
            Hostname = unicode:characters_to_list(Host),
            Port = maps:get(port, Parts, 80),
            {ok, Hostname, Port, DefOpts, State};
        _ ->
            not_supported
    end.


%--- Internal Functions --------------------------------------------------------

-ifdef(EMULATE_HARDWARE).

-define(DEVICE_FILE, <<"dummy.img">>).
% Bootloader/Env + Reserved + Boot + System A + System B
-define(DEVICE_SIZE, ((5 + 128 + 64 + 256 + 256) * (1024 * 1024))).

uboot_load_env() ->
    uboot_parse_env(#{
        <<"alloy_env_ver">> => ?ALLOY_ENV_VER,
        <<"system_architecture">> => <<"aarch64-unknown-linux-gnu">>,
        <<"system_platform">> => <<"kontron-albl-imx8mm">>,
        <<"active_system">> => <<"a">>,
        <<"valid_system">> => <<"a">>,
        <<"upgrade_available">> => <<"0">>,
        <<"rollback_available">> => <<"0">>,
        <<"bootcount">> => <<"0">>,
        <<"bootlimit">> => <<"3">>
    }).

uboot_save_env(UBootEnv) ->
    {ok, UBootEnv}.

kernel_load_args() ->
    {ok, #{
        <<"root">> => ?SYSTEM_A_DEVICE
    }}.

kernel_path(Path, SysId) ->
    % During emulation we store the kernel in the current directory
    iolist_to_binary([filename:basename(Path), kernel_postfix(SysId)]).

validate_firmware(_Meta, _UBootEnv) ->
    % During emulation, we are not validating the firmware
    ok.

init_target() ->
    DeviceFile = ?DEVICE_FILE,
    DeviceSize = ?DEVICE_SIZE,
    Target = #target{device = DeviceFile, offset = 0,
                     size = DeviceSize, total = DeviceSize},
    maybe
        {ok, File} ?= file:open(?DEVICE_FILE, [raw, write, read]),
        case file:pread(File, DeviceSize - 1, 1) of
            {error, Reason} -> {error, Reason};
            {ok, [_]} ->
                ok = file:close(File),
                {ok, Target};
            eof ->
                ok = file:pwrite(File, DeviceSize - 1, <<0>>),
                ok = file:close(File),
                {ok, Target}
        end
    end.

-else. % EMULATE_HARDWARE is undefined

uboot_load_env() ->
    maybe
        {ok, UBootConfig} ?= grisp_uboot:configuration(?UBOOT_ENV_CONFIG),
        {ok, RawUBootEnv} ?= grisp_uboot:read(UBootConfig),
        {ok, _UBootEnv} ?= uboot_parse_env(RawUBootEnv)
    else
      {error, Reason} -> {error, {failed_to_uboot_load_env, Reason}}
    end.

uboot_save_env(#uboot_env{raw_env = RawEnv} = UBootEnv) ->
    maybe
        {ok, UBootConfig} ?= grisp_uboot:configuration(?UBOOT_ENV_CONFIG),
        ok ?= grisp_uboot:write(RawEnv, UBootConfig),
        [] ?= os:cmd("sync"),
        {ok, UBootEnv}
    else
      {error, Reason} -> {error, {failed_to_uboot_save_env, Reason}};
      Reason when is_list(Reason) ->
        {error, {sync_failed, unicode:characters_to_binary(Reason)}}
    end.

kernel_load_args() ->
    maybe
        {ok, Data} ?= file:read_file(<<"/proc/cmdline">>),
        Line = case binary:match(Data, <<"\n">>) of
            {Pos, _Len} -> binary:part(Data, 0, Pos);
            nomatch -> Data
        end,
        Pairs = [kernel_parse_arg(T)
                    || T <- binary:split(Line, <<" ">>, [global, trim_all]),
                       T =/= <<>>],
        {ok, maps:from_list(Pairs)}
    else
      {error, Reason} -> {error, {failed_to_kernel_load_args, Reason}}
    end.

kernel_parse_arg(Token) ->
    case binary:split(Token, <<"=">>, []) of
        [Key, Value] -> {Key, Value};
        [Key] -> {Key, <<>>}
    end.

kernel_path(Path, SysId) ->
    iolist_to_binary([Path, kernel_postfix(SysId)]).

validate_firmware(#{architecture := Arch, platform := Platform},
                  #uboot_env{architecture = Arch, platform = Platform}) ->
    ok;
validate_firmware(#{architecture := Arch, platform := Platform}, _UBootEnv) ->
    {error, {unexpected_firmware_architecture_or_platform, Arch, Platform}};
validate_firmware(#{}, _UBootEnv) ->
    {error, firmware_without_architecture_or_platform}.

init_target() ->
    #target{device =?GLOBAL_DEVICE, offset = 0}.

-endif.

other_system(0) -> 1;
other_system(1) -> 0.

uboot_parse_env(#{<<"alloy_env_ver">> := ?ALLOY_ENV_VER,
                  <<"system_architecture">> := Architecture,
                  <<"system_platform">> := Platform,
                  <<"active_system">> := ActiveSystem,
                  <<"valid_system">> := ValidSystem,
                  <<"upgrade_available">> := UpgradeAvailable,
                  <<"rollback_available">> := RollbackAvailable,
                  <<"bootcount">> := BootCount,
                  <<"bootlimit">> := BootLimit} = RawUBootEnv) ->
    try
        {ok, #uboot_env{
            raw_env = RawUBootEnv,
            architecture = Architecture,
            platform = Platform,
            active = uboot_parse_system(ActiveSystem),
            valid = uboot_parse_system(ValidSystem),
            upgrading = uboot_parse_bool(UpgradeAvailable),
            rollback = uboot_parse_bool(RollbackAvailable),
            bootcount = uboot_parse_int(BootCount),
            bootlimit = uboot_parse_int(BootLimit)
        }}
    catch
        throw:Reason -> {error, Reason}
    end;
uboot_parse_env(#{<<"alloy_env_ver">> := BadVer})
  when BadVer =/= ?ALLOY_ENV_VER ->
    {error, {invalid_uboot_env_version, BadVer}};
uboot_parse_env(#{}) ->
    {error, invalid_uboot_env}.

uboot_parse_system(<<"a">>) -> 0;
uboot_parse_system(<<"b">>) -> 1;
uboot_parse_system(<<"r">>) -> removable;
uboot_parse_system(Sys) -> throw({invalid_uboot_env, Sys}).

uboot_parse_int(Value) ->
    try binary_to_integer(Value)
    catch
        error:badarg -> throw({invalid_uboot_env, Value})
    end.

uboot_parse_bool(<<"0">>) -> false;
uboot_parse_bool(<<"1">>) -> true;
uboot_parse_bool(Value) -> throw({invalid_uboot_env, Value}).

uboot_format_system(0) -> <<"a">>;
uboot_format_system(1) -> <<"b">>.

uboot_reset_metadata(0, RawEnv) ->
    RawEnv#{
        <<"systema_firmware_uuid">> => <<>>,
        <<"systema_firmware_version">> => <<>>,
        <<"systema_firmware_vcs_id">> => <<>>,
        <<"systema_firmware_author">> => <<>>
    };
uboot_reset_metadata(1, RawEnv) ->
    RawEnv#{
        <<"systemb_firmware_uuid">> => <<>>,
        <<"systemb_firmware_version">> => <<>>,
        <<"systemb_firmware_vcs_id">> => <<>>,
        <<"systemb_firmware_author">> => <<>>
    }.

uboot_update_metadata(0, Meta, RawEnv) ->
    RawEnv#{
        <<"systema_firmware_uuid">> => maps:get(uuid, Meta, <<>>),
        <<"systema_firmware_version">> => maps:get(version, Meta, <<>>),
        <<"systema_firmware_vcs_id">> => maps:get(vcs, Meta, <<>>),
        <<"systema_firmware_author">> => maps:get(author, Meta, <<>>)
    };
uboot_update_metadata(1, Meta, RawEnv) ->
    RawEnv#{
        <<"systemb_firmware_uuid">> => maps:get(uuid, Meta, <<>>),
        <<"systemb_firmware_version">> => maps:get(version, Meta, <<>>),
        <<"systemb_firmware_vcs_id">> => maps:get(vcs, Meta, <<>>),
        <<"systemb_firmware_author">> => maps:get(author, Meta, <<>>)
    }.

uboot_prepare_update(UBootEnv = #uboot_env{raw_env = RawEnv}, SysId) ->
    uboot_save_env(UBootEnv#uboot_env{
        upgrading = false,
        rollback = false,
        raw_env = uboot_reset_metadata(SysId, RawEnv#{
            <<"upgrade_available">> => <<"0">>,
            <<"rollback_available">> => <<"0">>
        })
    }).

uboot_finalize_update(UBootEnv = #uboot_env{raw_env = RawEnv}, Meta, SysId) ->
    uboot_save_env(UBootEnv#uboot_env{
        bootcount = 0,
        upgrading = true,
        raw_env = uboot_update_metadata(SysId, Meta, RawEnv#{
            <<"bootcount">> => <<"0">>,
            <<"upgrade_available">> => <<"1">>,
            <<"upgrade_fallback">> => <<"0">>
        })
    }).

uboot_cancel_update(UBootEnv = #uboot_env{raw_env = RawEnv}, SysId) ->
    uboot_save_env(UBootEnv#uboot_env{
        bootcount = 0,
        upgrading = false,
        raw_env = uboot_reset_metadata(SysId, RawEnv#{
            <<"bootcount">> => <<"0">>,
            <<"upgrade_available">> => <<"0">>,
            <<"upgrade_fallback">> => <<"0">>
        })
    }).

uboot_validate_update(UBootEnv = #uboot_env{raw_env = RawEnv}, SysId) ->
    uboot_save_env(UBootEnv#uboot_env{
        bootcount = 0,
        upgrading = false,
        rollback = true,
        valid = SysId,
        raw_env = uboot_reset_metadata(SysId, RawEnv#{
            <<"bootcount">> => <<"0">>,
            <<"upgrade_available">> => <<"0">>,
            <<"rollback_available">> => <<"1">>,
            <<"upgrade_fallback">> => <<"0">>,
            <<"valid_system">> => uboot_format_system(SysId)
        })
    }).

validate_active(#uboot_env{active = 0}, #{<<"root">> := ?SYSTEM_A_DEVICE}) -> ok;
validate_active(#uboot_env{active = 1}, #{<<"root">> := ?SYSTEM_B_DEVICE}) -> ok;
validate_active(#uboot_env{active = removable}, #{<<"root">> := ?SYSTEM_R_DEVICE}) -> ok;
validate_active(#uboot_env{active = Active}, #{<<"root">> := Root}) ->
    {error, {unexpected_active_system, Active, Root}}.

next_active(#uboot_env{valid = SysId, upgrading = false}) -> {ok, SysId};
next_active(#uboot_env{valid = SysId, upgrading = true,
                       bootcount = B, bootlimit = L}) when B < L ->
    {ok, other_system(SysId)};
next_active(#uboot_env{valid = SysId, upgrading = true,
                       bootcount = B, bootlimit = L}) when B >= L ->
    {ok, SysId}.

kernel_postfix(0) -> <<"_A">>;
kernel_postfix(1) -> <<"_B">>.


%% TLS Transport Options

load_ca_certificates() ->
    {Certs, Errors} =
        grisp_updater_tools:config_certificates(grisp_updater_kalblimx8mm,
                                server_ca_certificates, "*.{crt,cer,pem}"),
    lists:foreach(fun
        ({priv_not_found, AppName}) ->
            ?LOG_WARNING("Application ~s priv directory not found", [AppName]);
        ({invalid_file_or_directory, Path}) ->
            ?LOG_WARNING("Invalid certificate file or directory: ~s", [Path]);
        ({read_error, Reason, Path}) ->
            ?LOG_WARNING("Failed to read CA certificates from ~s (~p)", [Path, Reason]);
        (Reason) ->
            ?LOG_WARNING("Error loading some server CA cerificates: ~p", [Reason])
    end, Errors),
    if Certs =:= [] ->
        ?LOG_WARNING("No valid CA certificates specified");
        true -> ok
    end,
    Certs.

prepare_tls_transport_options(_Opts) ->
    CACerts = load_ca_certificates(),
    [{verify, verify_peer}, {cacerts, CACerts}].

tls_options(#http_state{tls_trans_opts = TransOpts}, Host, DefOpts) ->
    DefOpts#{
        transport => tls,
        transport_opts => [
            {server_name_indication, unicode:characters_to_list(Host)}
            | TransOpts
        ]
    }.
