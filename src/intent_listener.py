#!/usr/bin/env python2
import grpc
import json
import os
import subprocess
import sys

from flask import Flask, request
from p4codegen import P4CodeGenerator

# Import P4Runtime lib from parent utils dir
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
import p4runtime_lib.simple_controller
from p4runtime_lib.error_utils import printGrpcError

INTENT_FILENAME = "intent-2.txt"
app = Flask(__name__)

##############


def run_external_program(shell_command):
    p = subprocess.Popen(shell_command, shell=True,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in p.stdout.readlines():
        print line,
    return p.wait()

def generate_p4code_from_intent(intent_fname="intent-2.txt",
                                p4code_fname="s1_running.p4"):
    print "Reading intents from %s." % intent_fname
    gen = P4CodeGenerator(intent_fname)
    print "Parsing intents."
    gen.process_intents()
    print "Outputing p4 code to %s." % p4code_fname
    gen.generate_p4code(p4code_fname)

def process_new_p4code(topo_file="./topology.json",
                       p4info_file_path="./build/s1_running.p4info",
                       bmv2_file_path="./build/s1_running.json"):
    # Generate the new P4 code from intent-2.txt
    generate_p4code_from_intent()
    # Compile the P4 code into p4info and BMV2's JSON pipeline config files
    retval = run_external_program("p4c-bm2-ss --p4v 16 --p4runtime-file build/"
                                  "s1_running.p4info --p4runtime-format "
                                  "text -o build/s1_running.json s1_running.p4")

    with open(topo_file, 'r') as f:
        topo = json.load(f)
    switches = topo['switches']
    s1_runtime_json = switches['s1']['runtime_json']
    with open(s1_runtime_json, 'r') as sw_conf_file:
        s1_dict = p4runtime_lib.simple_controller.json_load_byteified(sw_conf_file)

    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')

        s1.MasterArbitrationUpdate()
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s1"

        table_entries = s1_dict['table_entries']
        print "Inserting %d table entries..." % len(table_entries)
        for entry in table_entries:
            print p4runtime_lib.simple_controller.tableEntryToString(entry)
            p4runtime_lib.simple_controller.insertTableEntry(s1, entry, p4info_helper)
        print "Installed table entries on s1"

    except grpc.RpcError as e:
        printGrpcError(e)


@app.route('/intent', methods=['POST'])
def process_intent():
    process_new_p4code()

    with open("s1_running.p4", 'r') as fh:
        p4code = fh.read()

    return json.dumps({'success': True, 'p4code': p4code}), 200


def main():
    host = "0.0.0.0"
    port = 5050
    app.run(host=host, port=port, debug=True)


if __name__ == '__main__':
    main()
