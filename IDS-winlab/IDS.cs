using System.Collections.Generic;
using NdisApiDotNet;
using NdisApiDotNetPacketDotNet.Extensions;
using PacketDotNet;
using System.Threading;
using System.Timers;
using System.Windows.Forms;
namespace IDS_winlab
{
    public class IDS
    {
        int ksyn = 0;
        public void SYNFloodDetector(NdisApi filter, WaitHandle[] waitHandles, IReadOnlyList<NetworkAdapter> networkAdapters, IReadOnlyList<ManualResetEvent> waitHandlesManualResetEvents, Form1 form)
        {
			var ndisApiHelper = new NdisApiHelper();
			var ethRequest = ndisApiHelper.CreateEthRequest();
			System.Timers.Timer aTimer = new System.Timers.Timer(); //Создаем таймер
			aTimer.Elapsed += new ElapsedEventHandler(OnTimedEvent); //добавляем событие под конец таймера
			aTimer.Interval = 1000; //1 sec
			aTimer.Enabled = true;
			int n = 1;

			while (true)
			{
				var handle = WaitHandle.WaitAny(waitHandles);
				ethRequest.AdapterHandle = networkAdapters[handle].Handle;
				while (filter.ReadPacket(ref ethRequest) && n == 1)
				{
					var packet = ethRequest.Packet;
					var ethPacket = packet.GetEthernetPacket(ndisApiHelper);
					if (ethPacket.PayloadPacket is IPv4Packet iPv4Packet)
					{
						if (iPv4Packet.PayloadPacket is TcpPacket tcpPacket)
						{
							// Обнаружение флага SYN в TCP пакете
							if (tcpPacket.Syn)
							{
								ksyn += 1;
								form.UpdateTxt($"\r\n{iPv4Packet.SourceAddress}:{tcpPacket.SourcePort} -> {iPv4Packet.DestinationAddress}:{tcpPacket.DestinationPort} | Флаг: SYN");
								if (ksyn > 1)
								{
									MessageBox.Show($"Зафиксировано аномальное количество SYN-запросов: более {ksyn - 1} запросов в секунду.\r\n" +
									$"Вероятно, осуществляется SYN-флуд атака по порту {tcpPacket.DestinationPort}!", "Обнаружена атака");
									n = 0;
									aTimer.Enabled = false;
									return;
								}
							}
						}
					}
					//Отправка пакетов дальше
					filter.SendPacket(ref ethRequest);
				}
				waitHandlesManualResetEvents[handle].Reset();
			}
		}
        public void OnTimedEvent(object source, ElapsedEventArgs e)
        {
            ksyn = 0;
        }
    }
}