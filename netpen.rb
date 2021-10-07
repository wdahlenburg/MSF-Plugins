#
# $Id$
# $Revision$
#
# Wyatt Dahlenburg (@wdahlenb)
#

module Msf
  class Plugin::NetPen < Msf::Plugin
    class NetPenDispatcher
      include Msf::Ui::Console::CommandDispatcher

      def name
        'Network Pentest Toolset'
      end

      def commands
        {
          'grab_web' => 'List all web related hosts in host:port format to be passed into httprobe',
          'grab_host_port' => 'List all related hosts in host:port format based on searchable parameters',
          'list_services' => 'List all open services'
        }
      end

      def cmd_grab_web(*_args)
        results = []

        # Grab all services matching 'http' type
        http_services = framework.db.services.where(state: 'open').select { |s| s.name.include? 'http' }
        http_services.each do |h|
          host = framework.db.hosts(id: h.host_id)[0]
          ip = host.address
          results << "#{ip}:#{h.port}"
        end

        # Grab all hosts on port 80 and 443
        web_services = framework.db.services.where(state: 'open').select { |s| s.port == 80 || s.port == 443 }
        web_services.each do |w|
          host = framework.db.hosts(id: w.host_id)[0]
          ip = host.address
          results << "#{ip}:#{w.port}"
        end

        results.uniq!

        results.each do |r|
          print "#{r}\n"
        end
      end

      def cmd_grab_host_port(*args)
        opts = Rex::Parser::Arguments.new(
          '-S' => [false, 'Search for a service string'],
          '-p' => [false, 'Inlude specific ports in results (Ex: 80,443-445)']
        )

        query = nil
        ports = nil

        opts.parse(args) do |opt, idx, _val|
          case opt
          when '-h'
            print_line('Usage: grab_host_port [-S http] [-p 80,443]')
            print_line(opts.usage)
            return
          when '-S'
            query = args[idx + 1]
          when '-p'
            ports = args[idx + 1]
          end
        end

        if query.nil? && ports.nil?
          print_line(opts.usage)
          return
        end

        results = []

        unless query.nil?
          http_services = framework.db.services.where(state: 'open').select { |s| s.name.include? query }
          http_services.each do |h|
            host = framework.db.hosts(id: h.host_id)[0]
            ip = host.address
            results << "#{ip}:#{h.port}"
          end
        end

        unless ports.nil?
          port_list = Rex::Socket.portspec_crack(ports)
          port_services = framework.db.services.where(state: 'open').select { |s| port_list.include? s.port }
          port_services.each do |p|
            host = framework.db.hosts(id: p.host_id)[0]
            ip = host.address
            results << "#{ip}:#{p.port}"
          end
        end

        results.uniq!

        results.each do |r|
          print "#{r}\n"
        end
      end

      def cmd_list_services(*_args)
        services = framework.db.services.where(state: 'open').pluck(:name).map { |s| s.sub('ssl/', '') }

        service_dictionary = {}

        services.each_with_index do |s, _i|
          service_dictionary[s] = services.count(s)
        end

        service_dictionary = service_dictionary.sort_by { |_k, v| v }.reverse.to_h

        service_dictionary.each do |k, _v|
          print "#{k}\n"
        end
      end
    end

    def name
      'Network Pentest Toolset'
    end

    def desc
      'Toolset to assist with basic network pentest tools by leveraging the MSF DB'
    end

    def initialize(framework, opts)
      super
      add_console_dispatcher(NetPenDispatcher)
    end

    def cleanup
      remove_console_dispatcher('Network Pentest Toolset')
    end
  end
end
