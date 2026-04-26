using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.Log;
using Com.AugustCellars.CoAP.Net;
using Com.AugustCellars.CoAP.OSCOAP;
using Com.AugustCellars.CoAP.Server;
using Makaretu.Dns;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.Extensions.Logging;
using OpenKNX.IoT.Classes;
using OpenKNX.IoT.Database;
using OpenKNX.IoT.Enums;
using OpenKNX.IoT.Helper;
using OpenKNX.IoT.Models;
using OpenKNX.IoT.Resources;
using OpenKNX.IoT.Resources.wellknwon;
using OpenKNX.IoT.Resources.wellknwon.knx;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Formats.Cbor;
using System.Net;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using static Com.AugustCellars.CoAP.Net.Exchange;

namespace OpenKNX.IoT
{
    public class KnxIotDevice
    {
        public event EventHandler<GroupMessageEvent>? GroupMessageReceived;

        private ILogger<KnxIotDevice>? _logger;
        private CoapServer _coapServer;
        private string _basePath = string.Empty;
        private MulticastService _mdns = new MulticastService();
        private ILoggerFactory? _loggerFactory;
        private ResourceContext _context;
        private DeviceData? _deviceData;
        private ResourceHelper _resourceHelper;
        private GroupObjectHelper _groupObjectHelper;

        public KnxIotDevice(string basePath = "")
        {
            _coapServer = new CoapServer();
            _basePath = basePath;

            _context = new ResourceContext();
            _context.Database.Migrate();

            _resourceHelper = new(_context);
            _groupObjectHelper = new(_resourceHelper);
            _groupObjectHelper.GroupMessageReceived += _groupObjectHelper_GroupMessageReceived;
        }

        public KnxIotDevice(ILoggerFactory loggerFactory, string basePath = "")
        {
            _logger = loggerFactory.CreateLogger<KnxIotDevice>();
            _loggerFactory = loggerFactory;
            _basePath = basePath;

            CoapConfig config = new CoapConfig();
            config.TokenLength = 8;
            _coapServer = new CoapServer(config, [49124]);

            _context = new ResourceContext();
            _context.Database.Migrate();

            _resourceHelper = new(_context, _loggerFactory);
            _groupObjectHelper = new(_resourceHelper, _loggerFactory);
            _groupObjectHelper.GroupMessageReceived += _groupObjectHelper_GroupMessageReceived;

            LogManager.Level = Com.AugustCellars.CoAP.Log.LogLevel.Debug;
            LogManager.Instance = new FileLogManager(new LoggerTextWriter("CoAP", _loggerFactory, Microsoft.Extensions.Logging.LogLevel.Debug));
        }

        private void _groupObjectHelper_GroupMessageReceived(object? sender, GroupMessageEvent e)
        {
            GroupMessageReceived?.Invoke(this, e);
        }

        public void SendGroupMessage(string href, object value)
        {
            _groupObjectHelper.SendGroupMessage(href, value);
        }

        IEnumerable<IPAddress> GetLocalIPv6()
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .Where(nic =>
                    nic.OperationalStatus == OperationalStatus.Up)
                .SelectMany(nic => nic.GetIPProperties().UnicastAddresses)
                .Where(ua =>
                    ua.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                .Select(ua => ua.Address);
        }

        public void Start(InitialDeviceConfig config)
        {
            _logger?.LogInformation("Starting KNX IoT device...");

            LoadSecurityContexts();

            _deviceData = new DeviceData(config, _resourceHelper);

            var x = _coapServer.FindResource(".well-known");
            x.Add(new WellknownCore(_deviceData));
            x.Add(new KnxResource(_deviceData, _loggerFactory));
            _coapServer.Add(new DevResource(_deviceData, _loggerFactory));
            _coapServer.Add(new ApplicationProgramResource(_deviceData));
            _coapServer.Add(new ActionResource(_deviceData, _loggerFactory));
            _coapServer.Add(new FunctionPointsResource(_deviceData, _loggerFactory));
            _coapServer.Add(new AuthenticationResource(_deviceData, _loggerFactory));
            _coapServer.Add(new ParameterResource(_deviceData, _loggerFactory));
            _coapServer.Add(new MessagingResource(_groupObjectHelper));

            _coapServer.Start();

            IPEndPoint endPoint = new IPEndPoint(IPAddress.Parse("ff02::fd"), 5683);
            _coapServer.AddMulticastAddress(endPoint);
            JoinGroupAddresses();

            foreach (var endpoint in _coapServer.EndPoints)
            {
                _logger?.LogInformation($"CoAP server listening on {endpoint.LocalEndPoint}");
            }

            _logger?.LogInformation("Advertising service via mDNS...");
            var sd = new ServiceDiscovery(_mdns);
            //_mdns.QueryReceived += (s, e) =>
            //{
            //    var names = e.Message.Questions
            //        .Select(q => q.Name + " " + q.Type);
            //    _logger?.LogInformation($"got a query for {String.Join(", ", names)}");
            //};

            var z1 = new ServiceProfile(config.Serialnumber, "_knx._udp", 5353);
            sd.Advertise(z1);
            _mdns.UseIpv4 = false;

            
            _mdns.Start();

            var ipv6Addresses = GetLocalIPv6();
            foreach (var ip in ipv6Addresses)
            {
                var aaaa = new AAAARecord
                {
                    Name = $"knx-{config.Serialnumber}.local",
                    Address = ip
                };

                _mdns.SendAnswer(new Makaretu.Dns.Message
                {
                    QR = true,
                    AA = true,
                    Answers = { aaaa }
                });
            }

        }

        private void LoadSecurityContexts()
        {
            _logger?.LogInformation("Loading Security Context");

            byte[] keyIdContext = Convert.FromHexString("0D");
            byte[] keyId = Convert.FromHexString("0C00FA10020701");
            byte[] masterSecret = Convert.FromHexString("3194BB0BCC341407F06F2A4A837EB4E2");
            long sequenceNumber = 0xa0;

            List<TokenEntry> entries = _resourceHelper.GetResourceEntryObject<List<TokenEntry>>("/auth/at") ?? new();
            if(!entries.Any(e => e.ReceiveId == Convert.ToHexString(keyId) && e.KeyIdContext == Convert.ToHexString(keyIdContext)))
            {
                _logger?.LogWarning("No matching entry in authentication table for default security context. Adding default entry to authentication table.");
                TokenEntry entry = new TokenEntry
                {
                    Id = "0",
                    ReceiveId = Convert.ToHexString(keyId),
                    KeyIdContext = Convert.ToHexString(keyIdContext),
                    MasterSecret = masterSecret,
                    Profile = Profiles.CoapOscore,
                    Scope = new List<uint>(),
                    SequenceNumber = sequenceNumber
                };
                entries.Add(entry);
                _resourceHelper.SaveResourceEntry("/auth/at", entries);
            }

            foreach (var entry in entries)
            {
                keyIdContext = Convert.FromHexString(entry.KeyIdContext);
                byte[] sendId = Convert.FromHexString(entry.SendId);
                byte[] receiveId = Convert.FromHexString(entry.ReceiveId);

                SecurityContext ctx = SecurityContext.DeriveContext(entry.MasterSecret, keyIdContext, sendId, receiveId);
                ctx.GroupId = keyIdContext;
                ctx.Sender.SequenceNumber = entry.SequenceNumber;
                _coapServer.SecurityContexts.Add(ctx);
            }

            _coapServer.SecurityContexts.OscoreEvents += SecurityContexts_OscoreEvents;

            PrintAuthenticationTable();
        }

        private void PrintAuthenticationTable()
        {
            StringBuilder table = new();
            table.AppendLine($"Index | SenderId       | RecipientId    | IdContext      | SequenzNr | MasterSecret");
            table.AppendLine($"-------------------------------------------------------------------------------------------");
            
            List<TokenEntry> entries = _resourceHelper.GetResourceEntryObject<List<TokenEntry>>("/auth/at") ?? new();
            foreach (var entry in entries)
            {
                table.AppendLine($" {entry.Id,4} | {entry.SendId,-14} | {entry.ReceiveId,-14} | {entry.KeyIdContext,-14} | {entry.SequenceNumber,-9} | {Convert.ToHexString(entry.MasterSecret)}");
            }
            _logger?.LogInformation(table.ToString());
        }

        private SecurityContext AddNewTokenEntry(byte[] sendId, byte[] receiveId, byte[] groupId, byte[] masterSecret, List<uint> scope)
        {
            SecurityContext ctx = SecurityContext.DeriveContext(masterSecret, groupId, sendId, receiveId);
            ctx.GroupId = groupId;
            // TODO make ECHO Response to verify sequencenumber
            //ctx.Sender.SequenceNumber = entry.SequenceNumber;
            _coapServer.SecurityContexts.Add(ctx);

            TokenEntry entry = new TokenEntry
            {
                Id = "0",
                SendId = Convert.ToHexString(sendId),
                ReceiveId = Convert.ToHexString(receiveId),
                KeyIdContext = Convert.ToHexString(groupId),
                MasterSecret = masterSecret,
                Profile = Profiles.CoapOscore,
                Scope = scope,
                SequenceNumber = 0xa0
            };

            List<TokenEntry> entries = _resourceHelper.GetResourceEntryObject<List<TokenEntry>>("/auth/at") ?? new();
            entries.Add(entry);
            _resourceHelper.SaveResourceEntry("/auth/at", entries);

            return ctx;
        }

        private void SecurityContexts_OscoreEvents(object? sender, OscoreEvent e)
        {
            if(e.Code == OscoreEvent.EventCode.UnknownGroupIdentifier)
            {
                string keyId = Convert.ToHexString(e.KeyIdentifier);
                string groupId = Convert.ToHexString(e.GroupIdentifier);
                List<TokenEntry> entries = _resourceHelper.GetResourceEntryObject<List<TokenEntry>>("/auth/at") ?? new();
                TokenEntry? token = entries.SingleOrDefault(t => t.ReceiveId == keyId && t.KeyIdContext == groupId);

                if (token == null)
                {
                    _logger?.LogError($"Received OSCORE message with unknown group identifier. KeyId: {keyId}");
                    token = entries.SingleOrDefault(t => t.SendId == keyId);
                    if(token == null)
                    {
                        _logger?.LogError($"OSCORE event UnknownGroupIdentifier: groupId={groupId} => sendId={keyId} not found in authentication table.");
                        return;
                    }
                    
                    e.SecurityContext = AddNewTokenEntry([], e.KeyIdentifier, e.GroupIdentifier, token.MasterSecret, token.Scope);
                    return;
                }

                if(groupId.StartsWith(_deviceData?.IndividualAddress.ToString("X4") ?? ""))
                {
                    _logger?.LogError($"Received OSCORE message with unknown group identifier. KeyId: {keyId}, GroupId: {groupId} starts with device individual address.");
                    return;
                }

                //var ctx = SecurityContext.DeriveContext(token.MasterSecret, e.GroupIdentifier, [], e.KeyIdentifier);
                //ctx.GroupId = e.GroupIdentifier;
                //e.SecurityContext = ctx;
            }
        }

        public void Stop()
        {
            _coapServer.Stop();
            _mdns.Stop();
        }

        public DeviceInfo GetDeviceInfo()
        {
            int subnet = _deviceData?.IndividualAddress >> 8 ?? 0xFF;
            int devadr = _deviceData?.IndividualAddress & 0xFF ?? 0xFF;
            string physicalAddress = $"{subnet >> 4}.{subnet & 0xF}.{devadr}";
            string serial = _deviceData?.Serialnumber ?? "Undefined";

            long iid = _deviceData?.InstallationId ?? 0x00;
            string installation_id = (iid >> 32 & 0xFF).ToString("x");
            installation_id += ":";
            installation_id += (iid >> 16 & 0xFFFF).ToString("x");
            installation_id += ":";
            installation_id += (iid & 0xFFFF).ToString("x");

            string lsm = _deviceData?.LoadStateMachine.ToString() ?? "Undefined";
            string password = _deviceData?.Password ?? "Undefined";
            bool progmode = _deviceData?.ProgMode ?? false;
            return new DeviceInfo(physicalAddress, serial, installation_id, $"knx-{serial}", lsm, password, progmode);
        }

        public List<GenericInternalInfo> GetGroupObjectTableInfo()
        {
            List<GenericInternalInfo> infos = new();
            List<GroupObjectTableEntry> GroupObjects = _resourceHelper.GetResourceEntryObject<List<GroupObjectTableEntry>>("/fp/g") ?? new();

            foreach (GroupObjectTableEntry entry in GroupObjects)
            {
                GenericInternalInfo info = new(entry.Id.ToString(), entry.Href, entry.Flags?.ToString("X2"), infoList: entry.GroupAddresses?.Select(s => s.ToString("X4")).ToList());
                infos.Add(info);
            }
            return infos;
        }

        public List<GenericInternalInfo> GetAuthenticationTableInfo()
        {
            List<GenericInternalInfo> infos = new();
            List<TokenEntry> entries = _resourceHelper.GetResourceEntryObject<List<TokenEntry>>("/auth/at") ?? new();

            foreach (TokenEntry entry in entries)
            {
                GenericInternalInfo info = new(entry.Id,
                    entry.SendId,
                    entry.ReceiveId,
                    entry.KeyIdContext,
                    BitConverter.ToString(entry.MasterSecret ?? Array.Empty<byte>()),
                    entry.Profile.ToString(),
                    entry.Scope.Select(s => s.ToString("X4")).ToList());
                infos.Add(info);
            }
            return infos;
        }

        public List<GenericInternalInfo> GetParameterTableInfo()
        {
            List<GenericInternalInfo> infos = new();
            IEnumerable<ResourceData> entries = _context.Resources.Where(r => r.Id.StartsWith("/p/"));

            foreach(ResourceData entry in entries)
            {
                GenericInternalInfo info = new(entry.Id.ToString(), entry.ResourceType.ToString(), BitConverter.ToString(entry.Data));
                infos.Add(info);
            }

            return infos;
        }

        public List<GenericInternalInfo> GetPublisherTableInfo()
        {
            return GetPublisherRecipientTableInfo("/p");
        }

        public List<GenericInternalInfo> GetRecipientTableInfo()
        {
            return GetPublisherRecipientTableInfo("/r");
        }

        private List<GenericInternalInfo> GetPublisherRecipientTableInfo(string type)
        {
            List<GenericInternalInfo> infos = new();
            List<RecipientPublisherEntry> entries = _resourceHelper.GetResourceEntryObject<List<RecipientPublisherEntry>>("/fp" + type) ?? new();

            foreach (RecipientPublisherEntry entry in entries)
            {
                long _groupId = entry.GroupId ?? 0;
                string groupId = (_groupId >> 16 & 0xFFFF).ToString("x4");
                groupId += ":";
                groupId += (_groupId & 0xFFFF).ToString("x4");
                GenericInternalInfo info = new(entry.Id.ToString(), groupId, infoList: entry.GroupAddresses?.Select(s => s.ToString("X4")).ToList());
                infos.Add(info);
            }
            return infos;
        }

        private void JoinGroupAddresses()
        {
            List<uint> groupIds = new();
            List<RecipientPublisherEntry> entries = _resourceHelper.GetResourceEntryObject<List<RecipientPublisherEntry>>("/fp/r") ?? new();
            entries.AddRange(_resourceHelper.GetResourceEntryObject<List<RecipientPublisherEntry>>("/fp/p") ?? new());
            foreach (var entry in entries)
            {
                if (entry.GroupId == null)
                    continue;
                if (!groupIds.Contains(entry.GroupId.Value))
                    groupIds.Add(entry.GroupId.Value);
            }

            long installationId = _resourceHelper.GetResourceEntry<long>("/dev/iia") ?? 0;
            // ff 32 00 30 fd 5e 1e 4f e5 67 00 00 ac c5 57 31
            foreach (uint groupId in groupIds)
            {
                string ip = "ff32:0030:fd";
                ip += (installationId >> 32 & 0xFF).ToString("x");
                ip += ":";
                ip += (installationId >> 16 & 0xFFFF).ToString("x");
                ip += ":";
                ip += (installationId & 0xFFFF).ToString("x");
                ip += ":";
                ip += "0000";
                ip += ":";
                ip += (groupId >> 16 & 0xFFFF).ToString("x4");
                ip += ":";
                ip += (groupId & 0xFFFF).ToString("x4");
                IPEndPoint remoteEndPoint = new IPEndPoint(IPAddress.Parse(ip), 5683);
                _logger?.LogInformation($"CoapServer joining multicast group {remoteEndPoint}");
                _coapServer.AddMulticastAddress(remoteEndPoint);
            }
        }
    }
}
