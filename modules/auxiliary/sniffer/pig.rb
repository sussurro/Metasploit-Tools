require 'msf/core'
require 'pp'


class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report
	include Msf::Exploit::Capture
	

	def initialize
		super(
			'Name'				=> 'Passive Information Gathering',
			'Version'           => '$Revision: 9929 $',
			'Description'       => 'This module sniffs packets and gathers information',
			'Author'			=> 'sussurro@happypacket.net',
			'License'			=> MSF_LICENSE,
			'Actions'			=>
				[
					[ 'Sniffer' ],
					[ 'List'    ]
				],
			'PassiveActions' =>
				[
					'Sniffer'
				],
			'DefaultAction'	 => 'Sniffer'
		)

		register_options([
			OptString.new('PROTOCOLS',	[true,	'A comma-delimited list of protocols to sniff or "all".', "all"]),
		], self.class)

		register_advanced_options([
			OptPath.new('ProtocolBase', [true,	'The base directory containing the protocol decoders',
				File.join(Msf::Config.install_root, "data", "exploits", "pig")
			]),
		], self.class)
	end


	def load_protocols
		base = datastore['ProtocolBase']
		if (not File.directory?(base))
			raise RuntimeError,"The ProtocolBase parameter is set to an invalid directory"
		end

		@protos = {}
		decoders = Dir.new(base).entries.grep(/\.rb$/).sort
		decoders.each do |n|
			f = File.join(base, n)
			m = ::Module.new
			begin
				m.module_eval(File.read(f, File.size(f)))
				m.constants.grep(/^Pig(.*)/) do
					proto = $1
					klass = m.const_get("Pig#{proto}")
					@protos[proto.downcase] = klass.new(framework, self)

					print_status("Loaded protocol #{proto} from #{f}...")
				end
			rescue ::Exception => e
				print_error("Decoder #{n} failed to load: #{e.class} #{e} #{e.backtrace}")
			end
		end
	end

	def run
		# Load all of our existing protocols
		load_protocols

		if(action.name == 'List')
			print_status("Protocols: #{@protos.keys.sort.join(', ')}")
			return
		end

		# Remove protocols not explicitly allowed
		if(datastore['PROTOCOLS'] != 'all')
			allowed = datastore['PROTOCOLS'].split(',').map{|x| x.strip.downcase}
			newlist = {}
			@protos.each_key { |k| newlist[k] = @protos[k] if allowed.include?(k) }
			@protos = newlist
		end

		print_status("Sniffing traffic.....")
		open_pcap
		i = 0
		each_packet do |pkt|
			eth = Racket::L2::Ethernet.new(pkt)
			ip = udp = tcp = nil
			@protos.each_key do |k|
				r = @protos[k].rules
				
				next if eth.ethertype == 2054
				match = true
				r[:eth].keys.each { |t|
					match = false if r[:eth][t] != eth.send(t)
				} if r[:eth]
				
				next if not match

				if eth.ethertype == 0
					data = {:raw => pkt, :eth => eth}
					next if r.keys.length > 1
					@protos[k].parse(data)
					next
				end
				
				if eth.ethertype == 0x0800 or eth.ethertype == 0x86dd
					ip = Racket::L3::IPv4.new(eth.payload) if not ip and eth.ethertype == 0x0800
					ip = Racket::L3::IPv6.new(eth.payload) if not ip and eth.ethertype == 0x86dd
					r[:ip].keys.each { |t|
						match = false  if r[:ip][t] != ip.send(t)
					} if r[:ip]
					next if not match
				else
					data = {:raw => pkt, :eth => eth}
					next if r.keys.length > 1
					@protos[k].parse(data)
					next
				end
				next if not ip

				next if ip and ip.version == 4 and not (ip.protocol == 6 or ip.protocol == 17)
				next if ip and ip.version == 6 and not (ip.nhead == 6 or ip.nhead == 17)
				data = {:raw => pkt, :eth => eth, :ip => ip}
				
				if r[:eth] and r[:ip] and r.keys.length  == 2
					@protos[k].parse(data)
					next
				end
				
				proto = ip.nhead if ip.version == 6	
				proto = ip.protocol if ip.version == 4	

				if proto == 6
					tcp = Racket::L4::TCP.new(ip.payload)
					r[:tcp].keys.each { |t|
						match = false if r[:tcp][t] != tcp.send(t)
					} if r[:tcp]
					next if not match
					data[:tcp] = tcp
					@protos[k].parse(data)
					next
				end
			
				if proto == 17
					udp = Racket::L4::UDP.new(ip.payload)
					r[:udp].keys.each { |t|
						
						match = false if r[:udp][t] != udp.send(t)
					} if r[:udp]

					next if not match

					data[:udp] = udp
					@protos[k].parse(data)
					next
				end
			end
			next


			if ip.protocol == 6
				tcp = Racket::L4::TCP.new(ip.payload)
				next if !(tcp.payload and tcp.payload.length > 0)
				data = {:raw => pkt, :eth => eth, :ip => ip, :tcp => tcp}
			else
				data = {:raw => pkt, :eth => eth, :ip => ip, :tcp => tcp}
			end

			true
		end
		close_pcap
		print_status("Finished sniffing")
	end
end

# End module class

class PigParser

	attr_accessor :rules, :framework , :module

	def initialize(framework,mod)
		self.framework = framework
		self.module = mod
		self.rules = {}
		register_rules()
	end

        def register_rules
                self.rules = {}
        end

	def parse(pkt)
		nil
	end

        def print_status(msg)
                self.module.print_status(msg)
        end

        def print_error(msg)
                self.module.print_error(msg)
        end

	def report_auth_info(*s)
		self.module.report_auth_info(*s)
	end

	def report_service(*s)
		self.module.report_service(*s)
	end

	def report_host(*s)
		self.module.report_host(*s)
	end

	def report_note(*s)
		self.module.report_note(*s)
	end

end

