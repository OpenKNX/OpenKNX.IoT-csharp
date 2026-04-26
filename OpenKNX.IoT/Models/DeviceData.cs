using OpenKNX.IoT.Database;
using OpenKNX.IoT.Enums;
using OpenKNX.IoT.Helper;
using OpenKNX.IoT.Resources.a;
using Org.BouncyCastle.Asn1.Mozilla;
using System;
using System.Collections.Generic;
using System.Text;

namespace OpenKNX.IoT.Models
{
    internal class DeviceData
    {
        public ResourceHelper _resourceHelper;

        public long InstallationId { get; private set; }
        public int IndividualAddress { get; private set; }
        public string Serialnumber { get; private set; }
        public bool ProgMode { get; set; } = false;

        public LoadStateMachineStates LoadStateMachine { get; private set; }

        public string Password { get; private set; }
        public int ManufacturerId { get; private set; }
        public string HardwareType { get; private set; }
        public string HardwareVersion { get; private set; }
        public string FirmwareVersion { get; private set; }
        public string Model { get; private set; }

        public DeviceData(InitialDeviceConfig config, ResourceHelper resourceHelper)
        {
            InstallationId = resourceHelper.GetResourceEntry<long>("/dev/iia") ?? 0;
            IndividualAddress = resourceHelper.GetResourceEntry<int>("/dev/ia") ?? 0xFFFF;
            LoadStateMachine = resourceHelper.GetResourceEntry<LoadStateMachineStates>("/a/lsm") ?? LoadStateMachineStates.Unloaded;

            Serialnumber = config.Serialnumber;
            Password = config.Password;
            ManufacturerId = int.Parse(Serialnumber.Substring(0, 4), System.Globalization.NumberStyles.HexNumber);
            HardwareType = config.HardwareType;
            HardwareVersion = config.HardwareVersion;
            FirmwareVersion = config.FirmwareVersion;
            Model = config.Model;
            _resourceHelper = resourceHelper;
        }

        public void SetInstallationId(long installationId)
        {
            InstallationId = installationId;
            _resourceHelper.SaveResourceEntry("/dev/iia", installationId);
        }

        public void SetIndividualAddress(int individualAddress)
        {
            IndividualAddress = individualAddress;
            _resourceHelper.SaveResourceEntry("/dev/ia", individualAddress);

            int subnet = (individualAddress >> 8) & 0xFF;
            int device = individualAddress & 0xFF;
            _resourceHelper.SaveResourceEntry("/dev/sna", subnet);
            _resourceHelper.SaveResourceEntry("/dev/da", device);
        }

        public void SetLoadStateMachine(LoadStateMachineStates state)
        {
            LoadStateMachine = state;
            _resourceHelper.SaveResourceEntry("/a/lsm", state);
        }
    }
}