import json
import logging
from time import sleep

"""
Process all of the auditd logs that were transformed to JSON from Laurel. Create an object for each log 
event and then, based on the type of key flags they have -> route them to the correct places in a dashboard
for monitoring. Over time, we will label these actions as good or bad and what action to take. Once we have
enough data we can bring someone in to build a ML algo to predict behavior of attackers and take steps to stop them.

Issues:
-if the attacker disables auditd or laurel fails, this breaks (will need to roll it into one thing). This is a POC.
-if the attacker is able to take advantadge of this script, they might be able to access they otherwise might not have.
"""


class Event:
    def __init__(self, id, record_type, record_type_contents, record_cwd=False, record_cwd_contents=False,
                 record_path=False, record_path_contents=False, record_process_title=False,
                 record_process_title_contents=False, parent_info=False, parent_info_contents=False):
        self.id = id
        self.record_type = record_type
        self.record_type_contents = record_type_contents
        self.record_cwd = record_cwd
        self.record_cwd_contents = record_cwd_contents
        self.record_path = record_path
        self.record_path_contents = record_path_contents
        self.record_process_title = record_process_title
        self.record_process_title_contents = record_process_title_contents
        self.parent_info = parent_info
        self.parent_info_contents = parent_info_contents

    '''
    Separate the tags based on the types. 
    '''

    def save(self):
        # Database object save method
        return print('Object SAVED to database! FOR DEBUGGING.')

    def delete(self):
        # Database delete save method
        return print('Object DELETED from database! FOR DEBUGGING.')

    def tags(self):
        try:
            return print(self.record_type_contents['key']) # todo: remove this print
        except KeyError:
            logging.exception("The system event likely doesn't have a tag associated with it.")
            raise


if __name__ == "__main__":
    # If it was Python 3.10 I would probably try out the match case statements for the first time.
    def object_creator(list_size, content):
        placement = list(content)
        if not list_size:
            return False
        else:
            if list_size == 1:
                print('List size was 1.')
            elif list_size == 2:
                # logging_event = Event(content.get(placement[0]), placement[1], content.get(placement[1]))
                print('LIst size was 2.')
            elif list_size == 2:
                print('List size was 3.')
            elif list_size == 3:
                print('List size was 4.')
            elif list_size == 4:
                print('List size was 5.')
            elif list_size == 5:
                logging_event = Event(content.get(placement[0]), placement[1], content.get(placement[1]), placement[2],
                                      content.get(placement[2]), placement[3], content.get(placement[3]), placement[4],
                                      content.get(placement[4]))
                logging_event.save()
                logging_event.delete()
                logging_event.tags()
            elif list_size == 6:
                print('List size was 6.')
            # I haven't seen one over 6 yet, but probably need to add some logging if we do have events over 6.
            else:
                return False


    with open(f'logs/audit.log', 'r') as audit_log:
        for event in audit_log:
            item = json.loads(event)
            if 'error' in item:
                pass
            else:
                # Some testing here, we will clean this up.
                positions = list(item)
                size = len(positions)
                object_creator(size, item)
                sleep(1)
